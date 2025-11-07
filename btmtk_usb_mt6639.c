// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MediaTek MT6639 Bluetooth USB Driver
 *
 * Based on reverse engineering of mtkbtfilterx.sys Windows driver
 * Supports MT6639 chipset with WMT protocol
 *
 * Copyright (C) 2025
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#define VERSION "1.0"

/* Vendor specific HCI commands */
#define HCI_OP_MTK_VENDOR_CMD		0xFC6F

/* WMT Opcodes */
#define WMT_OPCODE_TEST			0x00
#define WMT_OPCODE_PATCH_DOWNLOAD	0x01  /* Android driver uses 0x01 for firmware download */
#define WMT_OPCODE_EXIT			0x02
#define WMT_OPCODE_FUNC_CTRL		0x06
#define WMT_OPCODE_GET_FW_VER		0x08
#define WMT_OPCODE_GET_CHIP_ID		0x09
#define WMT_OPCODE_EFUSE_READ		0x0D
#define WMT_OPCODE_EFUSE_WRITE		0x0E
#define WMT_OPCODE_FEATURE_SET		0x0F
#define WMT_OPCODE_REGISTER_WRITE	0x10
#define WMT_OPCODE_REGISTER_READ	0x11

/* WMT Event */
#define WMT_EVT_VENDOR			0xE4
#define WMT_EVT_TYPE_WMT		0x02

/* Firmware download phases */
#define FW_PHASE_START			0x01
#define FW_PHASE_CONTINUE		0x02
#define FW_PHASE_END			0x03

/* MT6639 specific */
#define MT6639_CHIP_ID			0x6639
#define MT6639_FW_NAME			"mediatek/BT_RAM_CODE_MT6639_2_1_hdr.bin"

/* MT66xx firmware format (Android driver: btmtk_load_rom_patch_connac3) */
#define MTK_FW_TEXT_HEADER_SIZE		32  /* Text metadata + padding */
#define MTK_FW_GLOBAL_DESCR_OFFSET	32  /* Global descriptor at offset 32 */
#define MTK_FW_SECTION_MAP_OFFSET	96  /* Section maps start at offset 96 (0x60) */
#define MTK_FW_SECTION_MAP_SIZE		64  /* Each section map is 64 bytes */

/* Global Descriptor at offset 32 (Android: struct _Global_Descr) */
struct mtk_fw_global_descr {
	__le32 patch_ver;
	__le32 subsys;
	__le32 feature_opt;
	__le32 section_num;
} __packed;

struct mtk_fw_section_info_spec {
    __le32 dl_addr;       /* Download address in device memory */
    __le32 dl_size;       /* Size to download */
    __le32 sec_key_idx;
    __le32 align_len;
    __le32 sec_type2;
    __le32 dl_mode_crc;   /* Bits 16-23: bin_index, Bits 0-7: dl_mode */
    __le32 crc;
    __le32 reserved[6];
} __packed;

/* Section Map at offset 96+ (Android: struct _Section_Map) */
struct mtk_fw_section_map {
	__le32 sec_type;
	__le32 sec_offset;    /* Offset to section data in firmware file */
	__le32 sec_size;      /* Size of section */
	/* bin_info_spec union - 52 bytes */
	union {
	    struct {
		__le32 dl_addr;       /* Download address in device memory */
		__le32 dl_size;       /* Size to download */
		__le32 sec_key_idx;
		__le32 align_len;
		__le32 sec_type2;
		__le32 dl_mode_crc;   /* Bits 16-23: bin_index, Bits 0-7: dl_mode */
		__le32 crc;
		__le32 reserved[6];
	    };
	    struct mtk_fw_section_info_spec info_spec;
	};
} __packed;

/* Driver flags */
enum {
	BTMTK_FIRMWARE_LOADED,
	BTMTK_FUNC_ENABLED,
};

/* Maximum firmware segment size (Android driver uses 1024) */
#define FW_MAX_SEGMENT_SIZE	2048

struct btmtk_data {
	struct hci_dev *hdev;
	struct usb_device *udev;
	struct usb_interface *intf;

	unsigned long flags;

	/* USB endpoints */
	struct usb_anchor tx_anchor;
	struct usb_anchor intr_anchor;
	struct usb_anchor bulk_anchor;
	struct usb_anchor isoc_anchor;

	struct usb_endpoint_descriptor *intr_ep;
	struct usb_endpoint_descriptor *bulk_tx_ep;
	struct usb_endpoint_descriptor *bulk_rx_ep;

	/* Chip information */
	u16 chip_id;
	u16 fw_version;

	/* Firmware data */
	const struct firmware *fw;
	size_t fw_offset;
	size_t fw_section_size;  /* Size of BT firmware section */

	/* WMT command completion (for post-firmware responses via interrupt EP) */
	struct completion wmt_cmd_done;
	u8 wmt_evt_opcode;
	u8 wmt_evt_status;
};

/* WMT command structure (Windows driver format - SIMPLE!) */
struct wmt_cmd {
	u8 length;    /* Length of opcode + parameters */
	u8 opcode;    /* WMT opcode */
	u8 data[];    /* Parameters */
} __packed;

/* WMT event structure (Windows format) */
struct wmt_evt {
	u8 length;
	u8 event_type;  /* Should be 0x02 for WMT */
	u8 opcode;
	u8 status;
	u8 data[];
} __packed;

static const struct usb_device_id btmtk_table[] = {
	/* MediaTek MT6639 - Only match Bluetooth interface (Class E0, Subclass 01, Protocol 01) */
	{ USB_DEVICE_AND_INTERFACE_INFO(0x0489, 0xe13a, 0xe0, 0x01, 0x01) },
	{ USB_DEVICE_AND_INTERFACE_INFO(0x0e8d, 0x0608, 0xe0, 0x01, 0x01) },
	{ }
};

MODULE_DEVICE_TABLE(usb, btmtk_table);

/*
 * WMT Command Handling (Windows driver format)
 */

/* USB Vendor Request for reading events (Android driver) */
#define DEVICE_VENDOR_REQUEST_IN	0xC0  /* USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE */

static int btmtk_send_wmt_cmd(struct btmtk_data *data, const void *cmd_data,
			      int cmd_len, u8 expected_opcode)
{
	struct hci_dev *hdev = data->hdev;
	u8 *event_buf;
	int err, actual_len;
	int retries = 30;  /* 30 * 100ms = 3 seconds */

	pr_info("btmtk_usb_mt6639: Sending WMT cmd opcode=0x%02x len=%d\n",
		expected_opcode, cmd_len);

	/* Android driver: ALWAYS use control IN vendor request for WMT responses!
	 * Both before and after firmware load. */
	pr_info("btmtk_usb_mt6639: Using CONTROL IN vendor request for response\n");

	/* Allocate DMA-safe buffer (not on stack) for USB transfer */
	event_buf = kmalloc(256, GFP_KERNEL);
	if (!event_buf)
		return -ENOMEM;

	/* Send via HCI vendor command 0xFC6F using async send */
	err = __hci_cmd_send(hdev, HCI_OP_MTK_VENDOR_CMD, cmd_len, cmd_data);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: __hci_cmd_send failed: %d\n", err);
		bt_dev_err(hdev, "Failed to send WMT cmd: %d", err);
		kfree(event_buf);
		return err;
	}

	pr_info("btmtk_usb_mt6639: WMT command sent, waiting for device to prepare response...\n");

	/* MediaTek USB driver: Wait 100ms before FIRST read to give device time to process
	 * command and prepare response (WMT_DELAY_TIMES = 100, TIME_MULTIPL = 1000 microseconds)
	 * See linux_v2/usb/btmtkusb.c line 6145: usleep_range(delay * TIME_MULTIPL, ...) */
	msleep(100);

	pr_info("btmtk_usb_mt6639: Starting control IN polling for response (30 retries, 100ms interval)...\n");

	/* Android driver: Poll for response via USB control IN vendor request
	 * MT6639 in bootloader mode sends WMT responses via control pipe */
	while (retries-- > 0) {
		/* Log every 5th retry to avoid spam but show progress */
		if (retries % 5 == 0) {
			pr_info("btmtk_usb_mt6639: Control IN poll attempt (retries left: %d)\n", retries);
		}

		actual_len = usb_control_msg(data->udev,
					     usb_rcvctrlpipe(data->udev, 0),
					     0x01,                    /* bRequest */
					     DEVICE_VENDOR_REQUEST_IN, /* bmRequestType 0xC0 */
					     0x30,                    /* wValue */
					     0x00,                    /* wIndex */
					     event_buf, 256, 100);

		if (actual_len > 0) {
			pr_info("btmtk_usb_mt6639: *** CONTROL IN SUCCESS *** Got %d bytes\n", actual_len);
			/* Got data! Check if it's a WMT event */
			pr_info("btmtk_usb_mt6639: Control IN returned %d bytes\n", actual_len);
			if (actual_len >= 6) {
				pr_info("btmtk_usb_mt6639: RAW DATA: %*phD\n",
					min(actual_len, 32), event_buf);
			}

			/* Parse WMT vendor event 0xE4
			 * Control IN returns: E4 <len> 02 <opcode> <status> [data...]
			 * NOTE: No leading 0x04 HCI event header!
			 *
			 * MT6639 quirk: Device may respond with opcode 0x00 for certain commands
			 * (like firmware status query) instead of echoing the command opcode.
			 * Accept opcode 0x00 as valid if the status byte indicates success.
			 */
			if (actual_len >= 5 && event_buf[0] == 0xE4 && event_buf[2] == 0x02) {
				u8 wmt_opcode = event_buf[3];
				u8 wmt_status = event_buf[4];

				pr_info("btmtk_usb_mt6639: WMT event received: opcode=0x%02x status=0x%02x (expected 0x%02x)\n",
					wmt_opcode, wmt_status, expected_opcode);

				/* Check if opcode matches, OR if we got opcode 0x00 with valid status */
				bool opcode_ok = (wmt_opcode == expected_opcode) ||
						 (wmt_opcode == 0x00 && (wmt_status == 0x00 || wmt_status == 0x01));

				if (opcode_ok) {
					kfree(event_buf);
					/* Status 0x00 = success for firmware segments
					 * Status 0x01 = NEED_DOWNLOAD (success for query) */
					if (wmt_status == 0x00 || wmt_status == 0x01) {
						pr_info("btmtk_usb_mt6639: WMT command completed via control IN: opcode=0x%02x status=0x%02x\n",
							wmt_opcode, wmt_status);
						bt_dev_info(hdev, "WMT cmd completed via control IN: opcode=0x%02x status=0x%02x",
							   wmt_opcode, wmt_status);
						return 0;
					} else {
						bt_dev_err(hdev, "WMT cmd failed: opcode=0x%02x status=0x%02x",
							  wmt_opcode, wmt_status);
						pr_err("btmtk_usb_mt6639: WMT command rejected: opcode=0x%02x status=0x%02x\n",
						       wmt_opcode, wmt_status);
						return -EIO;
					}
				} else {
					pr_warn("btmtk_usb_mt6639: Opcode mismatch - got 0x%02x, expected 0x%02x (stale data? continuing...)\n",
						wmt_opcode, expected_opcode);
				}
			}
		} else if (actual_len < 0 && actual_len != -EAGAIN) {
			/* Log errors other than -EAGAIN (no data yet) */
			pr_warn("btmtk_usb_mt6639: Control IN error: %d\n", actual_len);
		}

		msleep(100);  /* Wait 100ms before next poll */
	}

	kfree(event_buf);
	bt_dev_err(hdev, "WMT command timeout opcode=0x%02x", expected_opcode);
	pr_err("btmtk_usb_mt6639: WMT command timeout for opcode 0x%02x\n", expected_opcode);
	return -ETIMEDOUT;
}

/* btmtk_send_wmt_reset removed - MT6639 in bootloader mode doesn't respond to WMT Reset */

static int btmtk_flush_control_endpoint(struct btmtk_data *data)
{
	u8 *buf;
	int actual_len;
	int flush_count = 0;
	int max_flushes = 10;

	pr_info("btmtk_usb_mt6639: Flushing control IN endpoint to clear stale data\n");

	buf = kmalloc(256, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Read control IN until no more data or max attempts reached */
	while (flush_count < max_flushes) {
		actual_len = usb_control_msg(data->udev,
					     usb_rcvctrlpipe(data->udev, 0),
					     0x01,                    /* bRequest */
					     DEVICE_VENDOR_REQUEST_IN, /* bmRequestType 0xC0 */
					     0x30,                    /* wValue */
					     0x00,                    /* wIndex */
					     buf, 256, 100);

		if (actual_len > 0) {
			pr_info("btmtk_usb_mt6639: Flushed %d bytes: %*phD\n",
				actual_len, min(actual_len, 32), buf);
			flush_count++;
		} else {
			/* No more data */
			pr_info("btmtk_usb_mt6639: Control endpoint flushed (%d stale responses removed)\n",
				flush_count);
			break;
		}

		msleep(50);  /* Small delay between reads */
	}

	kfree(buf);
	return 0;
}

static int btmtk_send_wmt_power_on(struct btmtk_data *data)
{
	/* Android driver: After firmware, send WMT POWER_ON (FUNC_CTRL) to enable BT
	 * From linux_v2/chip/btmtk_chip_common.c line 98:
	 * wmt_power_on_cmd = {0x01, 0x6F, 0xFC, 0x06, 0x01, 0x06, 0x02, 0x00, 0x00, 0x01}
	 *
	 * WMT format (sent as HCI 0xFC6F parameter):
	 *   0x01 - WMT packet type
	 *   0x06 - WMT opcode (FUNC_CTRL / POWER_ON)
	 *   0x02, 0x00 - WMT length = 2 bytes (LE)
	 *   0x00, 0x01 - Parameters (function=0 BT, enable=1) */
	u8 cmd[] = {
		0x01,              /* WMT packet type */
		0x06,              /* Opcode: FUNC_CTRL */
		0x02, 0x00,        /* WMT length = 2 bytes (LE) */
		0x00, 0x01         /* Params: function=0 (BT), enable=1 */
	};

	bt_dev_info(data->hdev, "Sending WMT POWER_ON (enable BT function)");
	pr_info("btmtk_usb_mt6639: WMT POWER_ON payload: %02x %02x %02x %02x %02x %02x\n",
		cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5]);

	/* CRITICAL: Flush control endpoint before sending POWER_ON
	 * The device may have stale responses cached from previous commands */
	btmtk_flush_control_endpoint(data);

	return btmtk_send_wmt_cmd(data, cmd, sizeof(cmd), 0x06);
}

static int btmtk_send_wmt_dma_complete(struct btmtk_data *data)
{
	/* Windows driver format for completion signal (final packet after firmware):
	 * Send empty PATCH_DOWNLOAD with no data to signal completion
	 * Based on Windows driver disassembly - last packet has flag=0x01
	 */
	u8 cmd[] = {
		0x01,        /* Direction: command */
		0x01,        /* Opcode: PATCH_DOWNLOAD */
		0x01, 0x00,   /* Param length = 1 (no data for completion) */
		0x03
	};

	bt_dev_info(data->hdev, "Sending firmware download completion");
	pr_info("btmtk_usb_mt6639: WMT DMA Complete payload: %02x %02x %02x %02x %02x\n",
		cmd[0], cmd[1], cmd[2], cmd[3], cmd[4]);
	return btmtk_send_wmt_cmd(data, cmd, sizeof(cmd), WMT_OPCODE_PATCH_DOWNLOAD);
}

/* EFEM command removed - Windows driver for MT66xx doesn't use it
 * If needed later, Windows uses opcode 0x0F (FEATURE_SET), not 0x55
 * Android's opcode 0x55 doesn't work for MT6639 */

static int btmtk_check_firmware_status(struct btmtk_data *data)
{
	/* Windows driver checks firmware status before loading
	 * Uses WMT GET_FW_VER (opcode 0x08) or checks device state
	 * For now, we'll always attempt to load
	 * TODO: Implement proper firmware version check
	 */
	bt_dev_info(data->hdev, "Checking firmware status...");

	/* If BTMTK_FIRMWARE_LOADED flag is set, firmware is already loaded */
	if (test_bit(BTMTK_FIRMWARE_LOADED, &data->flags)) {
		bt_dev_info(data->hdev, "Firmware already loaded, skipping");
		return 1;  /* 1 = already loaded */
	}

	bt_dev_info(data->hdev, "Firmware not loaded, will download");
	return 0;  /* 0 = needs loading */
}

/*
 * Firmware Loading for MT6639 (MT66xx series)
 */

static int btmtk_parse_fw_header_66xx(struct btmtk_data *data)
{
	const u8 *fw_data = data->fw->data;
	const struct mtk_fw_global_descr *global_descr;
	const struct mtk_fw_section_map *section_map;
	u32 section_num, i;
	u32 bt_section_offset = 0;
	u32 bt_section_size = 0;
	bool bt_section_found = false;

	pr_info("btmtk_usb_mt6639: Parsing firmware (section-based format)\n");
	pr_info("btmtk_usb_mt6639: Firmware size: %zu bytes\n", data->fw->size);

	/* Android driver: btmtk_load_rom_patch_connac3
	 * Firmware structure:
	 * - Bytes 0-31:  Text header (date/time/platform)
	 * - Bytes 32-47: Global Descriptor (section count, etc.)
	 * - Bytes 48-95: Padding
	 * - Bytes 96+:   Section Map array (64 bytes per section)
	 * - After maps:  Actual firmware data for each section
	 */
	if (data->fw->size < MTK_FW_SECTION_MAP_OFFSET + MTK_FW_SECTION_MAP_SIZE) {
		bt_dev_err(data->hdev, "Firmware too small: %zu bytes", data->fw->size);
		return -EINVAL;
	}

	/* Log text metadata (first 14 bytes show date/time) */
	pr_info("btmtk_usb_mt6639: Firmware metadata: %.14s\n", fw_data);

	/* Parse Global Descriptor at offset 32 */
	global_descr = (const struct mtk_fw_global_descr *)(fw_data + MTK_FW_GLOBAL_DESCR_OFFSET);
	section_num = le32_to_cpu(global_descr->section_num);

	pr_info("btmtk_usb_mt6639: Global Descriptor: sections=%u\n", section_num);

	if (section_num == 0 || section_num > 32) {
		bt_dev_err(data->hdev, "Invalid section count: %u", section_num);
		return -EINVAL;
	}

	/* Parse Section Maps starting at offset 96 to find BT firmware section */
	for (i = 0; i < section_num; i++) {
		u32 sec_offset, sec_size, dl_size, dl_mode_crc;
		u8 bin_index;

		section_map = (const struct mtk_fw_section_map *)
			(fw_data + MTK_FW_SECTION_MAP_OFFSET + (i * MTK_FW_SECTION_MAP_SIZE));

		sec_offset = le32_to_cpu(section_map->sec_offset);
		sec_size = le32_to_cpu(section_map->sec_size);
		dl_size = le32_to_cpu(section_map->dl_size);
		dl_mode_crc = le32_to_cpu(section_map->dl_mode_crc);

		/* Extract bin_index from bits 16-23 of dl_mode_crc */
		bin_index = (dl_mode_crc >> 16) & 0xFF;

		pr_info("btmtk_usb_mt6639: Section %u: offset=0x%06X size=%u dl_size=%u bin_index=%u\n",
			i, sec_offset, sec_size, dl_size, bin_index);

		/* Look for BT firmware section (bin_index = 1) */
		if (bin_index == 1) {
			bt_section_offset = sec_offset;
			bt_section_size = dl_size;
			bt_section_found = true;
			pr_info("btmtk_usb_mt6639: >>> Found BT firmware section (index %u) <<<\n", i);
			pr_info("btmtk_usb_mt6639: >>> Offset: 0x%06X (%u), Size: %u bytes <<<\n",
				bt_section_offset, bt_section_offset, bt_section_size);
			break;
		}
	}

	if (!bt_section_found) {
		bt_dev_err(data->hdev, "BT firmware section not found in firmware file");
		return -EINVAL;
	}

	/* Validate section offset and size */
	if (bt_section_offset + bt_section_size > data->fw->size) {
		bt_dev_err(data->hdev, "BT section beyond firmware file: offset=%u size=%u file_size=%zu",
			   bt_section_offset, bt_section_size, data->fw->size);
		return -EINVAL;
	}

	/* Store section info */
	data->fw_offset = bt_section_offset;
	data->fw_section_size = bt_section_size;

	bt_dev_info(data->hdev, "BT firmware section parsed: offset=%zu size=%zu",
		    data->fw_offset, data->fw_section_size);

	return 0;
}

static int btmtk_query_fw_status(struct btmtk_data *data)
{
	/* Query firmware status using empty PATCH_DOWNLOAD command
	 * Windows driver format: standard WMT packet with no parameters
	 * Device responds with status indicating if firmware load is needed
	 */
	u8 cmd[] = {
		0x01,        /* Direction: command */
		0x01,        /* Opcode: PATCH_DOWNLOAD */
		0x00, 0x00   /* Param length = 0 (query with no data) */
	};

	bt_dev_info(data->hdev, "Querying firmware download status");
	pr_info("btmtk_usb_mt6639: Sending firmware status query\n");

	return btmtk_send_wmt_cmd(data, cmd, sizeof(cmd), WMT_OPCODE_PATCH_DOWNLOAD);
}

static int btmtk_download_fw_section_info(struct btmtk_data *data, const struct mtk_fw_section_info_spec *info)
{
	struct hci_dev *hdev = data->hdev;
	u8 *cmd_buf;
	size_t cmd_len;
	u16 param_len;
	int err;

	/* Parameter length = everything after the 4-byte header */
	param_len = 2 + sizeof(*info);

	cmd_len = 4 + param_len;  /* direction + opcode + length + data */
	cmd_buf = kmalloc(cmd_len, GFP_KERNEL);
	if (!cmd_buf)
		return -ENOMEM;

	/* Build WMT patch download command (Windows driver format) */
	cmd_buf[0] = 0x01;                       /* Direction: command */
	cmd_buf[1] = WMT_OPCODE_PATCH_DOWNLOAD;  /* Opcode: 0x01 */
	cmd_buf[2] = param_len & 0xFF;           /* Param length low byte */
	cmd_buf[3] = (param_len >> 8) & 0xFF;    /* Param length high byte */
	cmd_buf[4] = 0x00;
	cmd_buf[5] = 0x01;
	memcpy(&cmd_buf[6], info, sizeof(*info));    /* Firmware data */

	bt_dev_dbg(hdev, "Downloading firmware section info: cmd_len %zu", cmd_len);

	err = btmtk_send_wmt_cmd(data, cmd_buf, cmd_len,
				 WMT_OPCODE_PATCH_DOWNLOAD);

	kfree(cmd_buf);
	return err;
}

static int btmtk_download_fw_segment(struct btmtk_data *data,
				     const u8 *fw_data, size_t fw_len)
{
	struct hci_dev *hdev = data->hdev;
	u8 *data_buf;
	int err;
	unsigned int pipe;
	int actual_len;

	data_buf = kmalloc(fw_len, GFP_KERNEL);
	if (!data_buf)
	    return -ENOMEM;

	memcpy(data_buf, fw_data, fw_len);

	pipe = usb_sndbulkpipe(data->udev, data->bulk_tx_ep->bEndpointAddress);
	err = usb_bulk_msg(data->udev, pipe, data_buf, fw_len, &actual_len, 500);
	if (err < 0) {
	    bt_dev_err(hdev, "btmtk_download_fw_segment: usb_bulk_msg returned %d", err);
	    goto err_free_buf;
	}

	if (actual_len < fw_len) {
	    bt_dev_err(hdev, "btmtk_download_fw_segment: only %d bytes out of %zu was sent", actual_len, fw_len);
	    err = -EINVAL;
	    goto err_free_buf;
	}

err_free_buf:
	kfree(data_buf);
	return err;
}

static int btmtk_load_firmware_section(struct btmtk_data *data, int section_num)
{
    const struct mtk_fw_section_map *section_info;
    const u8 *fw_ptr;
    size_t fw_remain;
    u8 phase;
    int err;
    int segment_count = 0;
    int max_segments;

    bt_dev_info(data->hdev, "Loading firmware section #%d", section_num);

    section_info = (struct mtk_fw_section_map*)(data->fw->data + MTK_FW_SECTION_MAP_OFFSET + section_num * MTK_FW_SECTION_MAP_SIZE);
    if (data->fw->size < section_info->sec_offset + section_info->sec_size) {
    	bt_dev_err(data->hdev, "Firmware truncated: %zu bytes too few", section_info->sec_offset + section_info->sec_size - data->fw->size);
    	return -EINVAL;
    }

    fw_ptr = data->fw->data + section_info->sec_offset;
    fw_remain = section_info->sec_size;

    /* Send section info to device */
    bt_dev_info(data->hdev, "Sending firmware section info to device");
    err = btmtk_download_fw_section_info(data, &section_info->info_spec);
    if (err < 0) {
	bt_dev_err(data->hdev, "Failed to upload firmware section info: %d", err);
	return err;
    }

    /* Calculate expected number of segments */
    max_segments = (fw_remain + FW_MAX_SEGMENT_SIZE - 1) / FW_MAX_SEGMENT_SIZE;
    bt_dev_info(data->hdev, "Downloading firmware section #%d: %zu bytes in %d segments", section_num, fw_remain, max_segments);

    pr_info("btmtk_usb_mt6639: ===== STARTING FIRMWARE LOAD =====\n");
    pr_info("btmtk_usb_mt6639: Section offset: 0x%06zX (%zu)\n", data->fw_offset, data->fw_offset);
    pr_info("btmtk_usb_mt6639: Section size: %zu bytes\n", fw_remain);
    pr_info("btmtk_usb_mt6639: Segments: %d (max %d bytes each)\n", max_segments, FW_MAX_SEGMENT_SIZE);

    while (fw_remain > 0) {
    	size_t segment_len = min_t(size_t, fw_remain, FW_MAX_SEGMENT_SIZE);
    
	/* Safety check: prevent infinite loop */
	if (segment_count >= max_segments + 10) {
	    bt_dev_err(data->hdev, "Firmware download stuck at segment %d (max %d)",
			segment_count, max_segments);
	    err = -ETIMEDOUT;
	    return err;
	}

	/* Determine phase */
	if (fw_ptr == data->fw->data + data->fw_offset) {
	    phase = FW_PHASE_START;
	    bt_dev_info(data->hdev, "Starting firmware download (segment 1/%d)",
			max_segments);
	} else if (fw_remain <= FW_MAX_SEGMENT_SIZE) {
	    phase = FW_PHASE_END;
	    bt_dev_info(data->hdev, "Sending final segment (%d/%d)",
			segment_count + 1, max_segments);
	} else {
	    phase = FW_PHASE_CONTINUE;
	}

	pr_info("btmtk_usb_mt6639: Segment %d/%d: offset=%zu len=%zu remain=%zu phase=%d\n",
		segment_count + 1, max_segments,
		fw_ptr - data->fw->data, segment_len, fw_remain, phase);

	err = btmtk_download_fw_segment(data, fw_ptr, segment_len);
	if (err < 0) {
	    bt_dev_err(data->hdev, "Failed to download segment %d: %d",
			segment_count + 1, err);
	    return err;
	}

	fw_ptr += segment_len;
	fw_remain -= segment_len;
	segment_count++;

	/* Progress indicator every 100 segments */
	if (segment_count % 100 == 0) {
	    bt_dev_info(data->hdev, "Progress: %d/%d segments (%d%%)",
			segment_count, max_segments,
			(segment_count * 100) / max_segments);
	}

	/* Small delay between segments */
	msleep(20);
    }

    bt_dev_info(data->hdev, "All %d firmware segments sent successfully",
		segment_count);

    /* Send DMA complete command */
    bt_dev_info(data->hdev, "Sending DMA complete");
    err = btmtk_send_wmt_dma_complete(data);
    if (err < 0) {
        bt_dev_err(data->hdev, "DMA complete failed: %d", err);
        return err;
    }

    /* Wait for firmware to initialize */
    msleep(500);

    return 0;
}

static int btmtk_load_firmware_66xx(struct btmtk_data *data)
{
	int err;

	bt_dev_info(data->hdev, "Loading firmware for MT6639 (MT66xx format)");

	/* Request firmware */
	err = request_firmware(&data->fw, MT6639_FW_NAME, &data->udev->dev);
	if (err < 0) {
		bt_dev_err(data->hdev, "Failed to load firmware %s: %d",
			   MT6639_FW_NAME, err);
		return err;
	}

	/* Windows driver: btmtk_parsing_fw_image for MT66xx */
	err = btmtk_parse_fw_header_66xx(data);
	if (err < 0)
		goto err_release_fw;

	/* Query firmware status before downloading (Android driver does this) */
	pr_info("btmtk_usb_mt6639: ===== QUERYING FIRMWARE STATUS =====\n");
	err = btmtk_query_fw_status(data);
	if (err < 0) {
		bt_dev_err(data->hdev, "Failed to query firmware status: %d", err);
		/* Continue anyway - device might still accept firmware */
		pr_info("btmtk_usb_mt6639: Status query failed, attempting download anyway\n");
	} else {
		pr_info("btmtk_usb_mt6639: Firmware status query successful, proceeding with download\n");
	}

	{
	    int sections[] = {1, 0, 3, 2, 4};
	    for (int idx = 0; idx < sizeof(sections) / sizeof(sections[0]); idx++) {
		int section_num = sections[idx];
		err = btmtk_load_firmware_section(data, section_num);
		if (err < 0) {
		    bt_dev_err(data->hdev, "Failed to load firmware section #%d: %d", section_num, err);
		    goto err_release_fw;
		}
	    }
	}

	bt_dev_info(data->hdev, "Firmware loaded successfully");
	set_bit(BTMTK_FIRMWARE_LOADED, &data->flags);

	release_firmware(data->fw);
	data->fw = NULL;
	return 0;

err_release_fw:
	release_firmware(data->fw);
	data->fw = NULL;
	return err;
}

/*
 * HCI Event Processing
 *
 * WMT events are handled synchronously via __hci_cmd_sync in btmtk_send_wmt_cmd
 */

/*
 * Forward declarations
 */
static int btmtk_submit_intr_urb(struct hci_dev *hdev, gfp_t mem_flags);
static int btmtk_submit_bulk_in_urb(struct hci_dev *hdev, gfp_t mem_flags);

/*
 * Device Setup
 */

static int btmtk_setup(struct hci_dev *hdev)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);
	int err;

	pr_info("btmtk_usb_mt6639: ========== SETUP BEGIN ==========\n");
	bt_dev_info(hdev, "MediaTek MT6639 Bluetooth setup");

	/* Disable autosuspend during setup */
	usb_disable_autosuspend(data->udev);

	/* CRITICAL: Select USB interface 0, alternate setting 0 (like Windows driver does) */
	pr_info("btmtk_usb_mt6639: Selecting USB interface 0, altsetting 0\n");
	err = usb_set_interface(data->udev, 0, 0);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: Failed to set USB interface: %d\n", err);
		bt_dev_err(hdev, "Failed to set USB interface: %d", err);
		return err;
	}
	pr_info("btmtk_usb_mt6639: USB interface selected successfully\n");

	/* Windows driver: Give device time to settle after interface change */
	pr_info("btmtk_usb_mt6639: Waiting 200ms for device to be ready after interface change\n");
	msleep(200);

	/* Kill any existing URBs from before interface change */
	usb_kill_anchored_urbs(&data->intr_anchor);
	usb_kill_anchored_urbs(&data->bulk_anchor);

	/* Ensure interrupt URB is submitted to receive responses */
	pr_info("btmtk_usb_mt6639: Submitting fresh interrupt URB after interface change\n");
	bt_dev_info(hdev, "Submitting interrupt URB for WMT event reception");
	err = btmtk_submit_intr_urb(hdev, GFP_KERNEL);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: Failed to submit interrupt URB: %d\n", err);
		bt_dev_err(hdev, "Failed to submit interrupt URB: %d", err);
		return err;
	}
	pr_info("btmtk_usb_mt6639: Interrupt URB submitted successfully\n");

	/* Also submit bulk IN URB - MediaTek devices may send events on bulk endpoint */
	pr_info("btmtk_usb_mt6639: Checking bulk anchor: empty=%d\n",
		usb_anchor_empty(&data->bulk_anchor));

	if (usb_anchor_empty(&data->bulk_anchor)) {
		pr_info("btmtk_usb_mt6639: Submitting bulk RX URB for event/data reception\n");
		bt_dev_info(hdev, "Submitting bulk RX URB for event/data reception");
		err = btmtk_submit_bulk_in_urb(hdev, GFP_KERNEL);
		if (err < 0) {
			pr_err("btmtk_usb_mt6639: Failed to submit bulk RX URB: %d\n", err);
			bt_dev_err(hdev, "Failed to submit bulk RX URB: %d", err);
			return err;
		}
		pr_info("btmtk_usb_mt6639: Bulk RX URB submitted successfully\n");
	} else {
		pr_info("btmtk_usb_mt6639: Bulk RX URB already submitted\n");
	}

	/* Give URBs time to be ready */
	msleep(100);

	/* NOTE: MT6639 in bootloader/ROM code mode does NOT respond to WMT commands
	 * Windows driver may send WMT Reset, but the device only responds AFTER firmware is loaded.
	 * Skip WMT Reset and go directly to firmware loading.
	 *
	 * If you want to test WMT Reset, uncomment the code below.
	 */
	pr_info("btmtk_usb_mt6639: Skipping WMT Reset - MT6639 only responds after firmware loaded\n");
	bt_dev_info(hdev, "MT6639 in ROM mode - loading firmware directly");

	/* COMMENTED OUT - Device doesn't respond in bootloader mode
	pr_info("btmtk_usb_mt6639: About to send WMT Reset\n");
	err = btmtk_send_wmt_reset(data);
	if (err < 0) {
		bt_dev_err(hdev, "WMT reset failed: %d", err);
		return err;
	}
	msleep(100);
	*/

	/* Check if firmware is already loaded */
	err = btmtk_check_firmware_status(data);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to check firmware status: %d", err);
		return err;
	} else if (err > 0) {
		/* Firmware already loaded, skip to function enable */
		bt_dev_info(hdev, "Skipping firmware download (already loaded)");
		goto enable_function;
	}

	/* Load firmware */
	pr_info("btmtk_usb_mt6639: ===== STARTING FIRMWARE LOAD =====\n");
	err = btmtk_load_firmware_66xx(data);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: Firmware loading failed: %d\n", err);
		bt_dev_err(hdev, "Firmware loading failed: %d", err);
		return err;
	}
	pr_info("btmtk_usb_mt6639: ===== FIRMWARE LOAD COMPLETE =====\n");

	/* Windows driver: Does NOT send EFEM after firmware load!
	 * Windows initialization sequence (MTK_BT_INIT_SEQUENCE.md):
	 *   1. Load firmware
	 *   2. DMA complete
	 *   3. (Optional) Register writes / eFuse operations
	 *   4. FUNC_CTRL (Enable BT function)
	 *
	 * Android driver uses EFEM (opcode 0x55) but this may be for different chip series.
	 * MT6639 follows Windows pattern - go directly to FUNC_CTRL after firmware.
	 *
	 * NOTE: If needed, Windows uses opcode 0x0F (FEATURE_SET) for eFEM, not 0x55.
	 * But it's not part of the standard initialization sequence.
	 */

	/* Wait for firmware to fully initialize
	 * PRIORITY 1 FIX: Increased from 1s to 5s to give device more time
	 * to initialize after firmware load. Android driver observations suggest
	 * device may need extended time before it's ready for POWER_ON. */
	pr_info("btmtk_usb_mt6639: Waiting 5 seconds for firmware initialization...\n");
	msleep(5000);  /* Increased from 1000ms to 5000ms */
	pr_info("btmtk_usb_mt6639: Firmware initialization wait complete\n");

	/* PRIORITY 1 FIX: Set FIRMWARE_LOADED flag NOW, before POWER_ON
	 * This allows interrupt handler to process WMT events on interrupt endpoint.
	 * Previously, flag was set AFTER POWER_ON, meaning interrupt handler
	 * wouldn't process the POWER_ON response even if device sent it via interrupt! */
	pr_info("btmtk_usb_mt6639: Setting FIRMWARE_LOADED flag (enables interrupt WMT processing)\n");
	set_bit(BTMTK_FIRMWARE_LOADED, &data->flags);

	/* Android driver (linux_v2/btmtk_main.c line 3105-3108):
	 * After firmware loads, send WMT POWER_ON (opcode 0x06) to enable BT function
	 *
	 * EFEM (opcode 0x55) is sent LATER in bt_open handler, not immediately after firmware */

enable_function:
	/* Send WMT POWER_ON to enable BT function */
	pr_info("btmtk_usb_mt6639: ===== ENABLING BT FUNCTION =====\n");

	bt_dev_info(hdev, "Sending WMT POWER_ON after firmware load...");
	err = btmtk_send_wmt_power_on(data);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to enable BT function: %d", err);
		return err;
	}

	/* Wait for chip to stabilize */
	msleep(1000);

	bt_dev_info(hdev, "MT6639 setup completed successfully");

	/* Re-enable autosuspend */
	usb_enable_autosuspend(data->udev);

	return 0;
}

static int btmtk_shutdown(struct hci_dev *hdev)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);

	bt_dev_info(hdev, "Shutting down MT6639");

	/* Kill any pending URBs */
	usb_kill_anchored_urbs(&data->intr_anchor);
	usb_kill_anchored_urbs(&data->bulk_anchor);

	return 0;
}

/*
 * USB Driver Interface
 */

static void btmtk_tx_complete(struct urb *urb)
{
	struct sk_buff *skb = urb->context;
	struct hci_dev *hdev = (struct hci_dev *)skb->dev;

	pr_info("btmtk_usb_mt6639: TX complete: status=%d\n", urb->status);

	if (urb->status != 0 && urb->status != -ENOENT && urb->status != -ESHUTDOWN)
		bt_dev_err(hdev, "TX URB failed: %d", urb->status);

	kfree(urb->setup_packet);
	kfree_skb(skb);
}

static void btmtk_bulk_in_complete(struct urb *urb)
{
	struct hci_dev *hdev = urb->context;
	struct sk_buff *skb;
	int err;

	pr_info("btmtk_usb_mt6639: *** BULK IN URB COMPLETE *** status=%d len=%d\n",
		urb->status, urb->actual_length);

	if (urb->status != 0) {
		if (urb->status != -ENOENT && urb->status != -ESHUTDOWN)
			bt_dev_err(hdev, "Bulk IN URB failed: %d", urb->status);
		return;
	}

	if (urb->actual_length == 0) {
		pr_info("btmtk_usb_mt6639: Bulk IN URB received 0 bytes\n");
		goto resubmit;
	}

	pr_info("btmtk_usb_mt6639: Received %d bytes on BULK IN EP\n", urb->actual_length);

	/* Allocate skb and copy data */
	skb = bt_skb_alloc(urb->actual_length, GFP_ATOMIC);
	if (!skb) {
		bt_dev_err(hdev, "Failed to allocate skb for bulk data");
		goto resubmit;
	}

	skb_put_data(skb, urb->transfer_buffer, urb->actual_length);

	/* Try as event first - WMT responses might come here */
	hci_skb_pkt_type(skb) = HCI_EVENT_PKT;

	/* Pass to HCI core */
	err = hci_recv_frame(hdev, skb);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to pass bulk data to HCI: %d", err);
		kfree_skb(skb);
	}

resubmit:
	/* Resubmit URB */
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0 && err != -EPERM && err != -ENODEV)
		bt_dev_err(hdev, "Failed to resubmit bulk IN URB: %d", err);
}

static void btmtk_intr_complete(struct urb *urb)
{
	struct hci_dev *hdev = urb->context;
	struct btmtk_data *data = hci_get_drvdata(hdev);
	struct sk_buff *skb;
	u8 *evt_data;
	int err;

	pr_info("btmtk_usb_mt6639: *** INTERRUPT URB COMPLETE *** status=%d len=%d\n",
		urb->status, urb->actual_length);
	bt_dev_dbg(hdev, "Interrupt URB completed: status=%d len=%d",
		   urb->status, urb->actual_length);

	if (urb->status != 0) {
		pr_warn("btmtk_usb_mt6639: Interrupt URB status=%d\n", urb->status);
		if (urb->status != -ENOENT && urb->status != -ESHUTDOWN)
			bt_dev_err(hdev, "Interrupt URB failed: %d", urb->status);
		return;
	}

	if (urb->actual_length == 0) {
		pr_info("btmtk_usb_mt6639: Interrupt URB received 0 bytes\n");
		goto resubmit;
	}

	pr_info("btmtk_usb_mt6639: ===== INTERRUPT EP RX ===== %d bytes\n", urb->actual_length);

	evt_data = urb->transfer_buffer;

	/* Log raw data for debugging */
	if (urb->actual_length <= 32) {
		pr_info("btmtk_usb_mt6639: RAW DATA: %*phD\n", urb->actual_length, evt_data);
	}

	/* Check if this is a WMT event (0x04 0xE4) - only after firmware loaded
	 * Format: 04 E4 <len> 02 <opcode> <status> [data...]
	 * HCI event header (0x04) + WMT vendor event (0xE4) */
	if (test_bit(BTMTK_FIRMWARE_LOADED, &data->flags) &&
	    urb->actual_length >= 6 &&
	    evt_data[0] == 0x04 &&  /* HCI Event packet indicator */
	    evt_data[1] == WMT_EVT_VENDOR &&  /* 0xE4 */
	    evt_data[3] == WMT_EVT_TYPE_WMT) {  /* 0x02 */
		u8 wmt_opcode = evt_data[4];
		u8 wmt_status = evt_data[5];

		pr_info("btmtk_usb_mt6639: *** WMT EVENT VIA INTERRUPT EP! *** opcode=0x%02x status=0x%02x\n",
			wmt_opcode, wmt_status);

		/* Store event data and signal completion */
		data->wmt_evt_opcode = wmt_opcode;
		data->wmt_evt_status = wmt_status;
		complete(&data->wmt_cmd_done);

		/* WMT event handled, don't pass to HCI core */
		goto resubmit;
	}

	/* Allocate skb and copy data */
	skb = bt_skb_alloc(urb->actual_length, GFP_ATOMIC);
	if (!skb) {
		bt_dev_err(hdev, "Failed to allocate skb for event");
		goto resubmit;
	}

	skb_put_data(skb, urb->transfer_buffer, urb->actual_length);
	hci_skb_pkt_type(skb) = HCI_EVENT_PKT;

	/* Pass to HCI core */
	err = hci_recv_frame(hdev, skb);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to pass event to HCI: %d", err);
		kfree_skb(skb);
	}

resubmit:
	/* Resubmit URB */
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0 && err != -EPERM && err != -ENODEV)
		bt_dev_err(hdev, "Failed to resubmit interrupt URB: %d", err);
}

static int btmtk_submit_intr_urb(struct hci_dev *hdev, gfp_t mem_flags)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);
	struct urb *urb;
	unsigned char *buf;
	unsigned int pipe;
	int err, size;

	pr_info("btmtk_usb_mt6639: submit_intr_urb() called\n");

	size = le16_to_cpu(data->intr_ep->wMaxPacketSize);
	pr_info("btmtk_usb_mt6639: Interrupt EP addr=0x%02x, maxpacket=%d, interval=%d\n",
		data->intr_ep->bEndpointAddress, size, data->intr_ep->bInterval);

	buf = kmalloc(size, mem_flags);
	if (!buf) {
		pr_err("btmtk_usb_mt6639: Failed to allocate interrupt buffer\n");
		return -ENOMEM;
	}

	urb = usb_alloc_urb(0, mem_flags);
	if (!urb) {
		pr_err("btmtk_usb_mt6639: Failed to allocate interrupt URB\n");
		kfree(buf);
		return -ENOMEM;
	}

	pipe = usb_rcvintpipe(data->udev, data->intr_ep->bEndpointAddress);

	usb_fill_int_urb(urb, data->udev, pipe, buf, size,
			 btmtk_intr_complete, hdev,
			 data->intr_ep->bInterval);

	urb->transfer_flags |= URB_FREE_BUFFER;

	usb_anchor_urb(urb, &data->intr_anchor);

	pr_info("btmtk_usb_mt6639: Submitting interrupt URB...\n");
	err = usb_submit_urb(urb, mem_flags);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: usb_submit_urb failed: %d\n", err);
		if (err != -EPERM && err != -ENODEV)
			bt_dev_err(hdev, "Failed to submit interrupt URB: %d", err);
		usb_unanchor_urb(urb);
	} else {
		pr_info("btmtk_usb_mt6639: Interrupt URB submitted, waiting for events...\n");
	}

	usb_free_urb(urb);

	return err;
}

static int btmtk_submit_bulk_in_urb(struct hci_dev *hdev, gfp_t mem_flags)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);
	struct urb *urb;
	unsigned char *buf;
	unsigned int pipe;
	int err, size;

	pr_info("btmtk_usb_mt6639: submit_bulk_in_urb() called\n");

	size = le16_to_cpu(data->bulk_rx_ep->wMaxPacketSize);
	pr_info("btmtk_usb_mt6639: Bulk RX EP addr=0x%02x, maxpacket=%d\n",
		data->bulk_rx_ep->bEndpointAddress, size);

	buf = kmalloc(size, mem_flags);
	if (!buf) {
		pr_err("btmtk_usb_mt6639: Failed to allocate bulk RX buffer\n");
		return -ENOMEM;
	}

	urb = usb_alloc_urb(0, mem_flags);
	if (!urb) {
		pr_err("btmtk_usb_mt6639: Failed to allocate bulk RX URB\n");
		kfree(buf);
		return -ENOMEM;
	}

	pipe = usb_rcvbulkpipe(data->udev, data->bulk_rx_ep->bEndpointAddress);

	usb_fill_bulk_urb(urb, data->udev, pipe, buf, size,
			  btmtk_bulk_in_complete, hdev);

	urb->transfer_flags |= URB_FREE_BUFFER;

	usb_anchor_urb(urb, &data->bulk_anchor);

	pr_info("btmtk_usb_mt6639: Submitting bulk RX URB...\n");
	err = usb_submit_urb(urb, mem_flags);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: bulk RX usb_submit_urb failed: %d\n", err);
		if (err != -EPERM && err != -ENODEV)
			bt_dev_err(hdev, "Failed to submit bulk RX URB: %d", err);
		usb_unanchor_urb(urb);
	} else {
		pr_info("btmtk_usb_mt6639: Bulk RX URB submitted, waiting for data...\n");
	}

	usb_free_urb(urb);

	return err;
}

static int btmtk_open(struct hci_dev *hdev)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);
	int err;

	bt_dev_dbg(hdev, "Opening device");

	err = usb_autopm_get_interface(data->intf);
	if (err < 0)
		return err;

	/* Submit interrupt URB to receive events */
	err = btmtk_submit_intr_urb(hdev, GFP_KERNEL);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to submit interrupt URB: %d", err);
		usb_autopm_put_interface(data->intf);
		return err;
	}

	return 0;
}

static int btmtk_close(struct hci_dev *hdev)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);

	bt_dev_dbg(hdev, "Closing device");

	/* Kill all pending URBs */
	usb_kill_anchored_urbs(&data->intr_anchor);
	usb_kill_anchored_urbs(&data->bulk_anchor);

	usb_autopm_put_interface(data->intf);

	return 0;
}

static int btmtk_flush(struct hci_dev *hdev)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);

	usb_kill_anchored_urbs(&data->tx_anchor);

	return 0;
}

static int btmtk_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct btmtk_data *data = hci_get_drvdata(hdev);
	struct usb_ctrlrequest *dr;
	struct urb *urb;
	unsigned int pipe;
	int err;

	pr_info("btmtk_usb_mt6639: send_frame() pkt_type=%d len=%d\n",
		hci_skb_pkt_type(skb), skb->len);

	/* Store hdev in skb for completion handler */
	skb->dev = (void *)hdev;

	switch (hci_skb_pkt_type(skb)) {
	case HCI_COMMAND_PKT:
		/* Send commands via control endpoint */
		pr_info("btmtk_usb_mt6639: Sending HCI command via control EP\n");
		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!urb) {
			pr_err("btmtk_usb_mt6639: Failed to allocate URB for command\n");
			return -ENOMEM;
		}

		dr = kmalloc(sizeof(*dr), GFP_ATOMIC);
		if (!dr) {
			pr_err("btmtk_usb_mt6639: Failed to allocate control request\n");
			usb_free_urb(urb);
			return -ENOMEM;
		}

		dr->bRequestType = USB_TYPE_CLASS | USB_RECIP_DEVICE;
		dr->bRequest = 0;
		dr->wIndex = cpu_to_le16(0);  /* Interface 0 */
		dr->wValue = cpu_to_le16(0);
		dr->wLength = cpu_to_le16(skb->len);

		pr_info("btmtk_usb_mt6639: Control request: type=0x%02x req=%d idx=%d len=%d\n",
			dr->bRequestType, dr->bRequest,
			le16_to_cpu(dr->wIndex), le16_to_cpu(dr->wLength));

		pipe = usb_sndctrlpipe(data->udev, 0);

		usb_fill_control_urb(urb, data->udev, pipe, (void *)dr,
				     skb->data, skb->len, btmtk_tx_complete, skb);

		hdev->stat.cmd_tx++;
		break;

	case HCI_ACLDATA_PKT:
		/* Send ACL data via bulk endpoint */
		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!urb)
			return -ENOMEM;

		pipe = usb_sndbulkpipe(data->udev, data->bulk_tx_ep->bEndpointAddress);

		usb_fill_bulk_urb(urb, data->udev, pipe, skb->data, skb->len,
				  btmtk_tx_complete, skb);

		hdev->stat.acl_tx++;
		break;

	case HCI_SCODATA_PKT:
		/* SCO not supported in this basic implementation */
		return -EOPNOTSUPP;

	default:
		return -EILSEQ;
	}

	usb_anchor_urb(urb, &data->tx_anchor);

	pr_info("btmtk_usb_mt6639: About to submit URB...\n");
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		pr_err("btmtk_usb_mt6639: usb_submit_urb FAILED: %d\n", err);
		if (err != -EPERM && err != -ENODEV)
			bt_dev_err(hdev, "Failed to submit URB: %d", err);
		kfree(urb->setup_packet);
		usb_unanchor_urb(urb);
		usb_free_urb(urb);
		return err;
	}

	pr_info("btmtk_usb_mt6639: URB submitted successfully\n");

	/* URB is now owned by USB core, will be freed in completion */
	usb_free_urb(urb);

	return 0;
}

static int btmtk_probe(struct usb_interface *intf,
		       const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *ep_desc;
	struct btmtk_data *data;
	struct hci_dev *hdev;
	int i, err;

	pr_info("btmtk_usb_mt6639: MediaTek MT6639 USB device detected\n");

	/* Allocate driver data */
	data = devm_kzalloc(&intf->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->udev = udev;
	data->intf = intf;

	init_usb_anchor(&data->tx_anchor);
	init_usb_anchor(&data->intr_anchor);
	init_usb_anchor(&data->bulk_anchor);
	init_usb_anchor(&data->isoc_anchor);

	/* Initialize WMT command completion for post-firmware interrupt endpoint responses */
	init_completion(&data->wmt_cmd_done);

	/* Find endpoints */
	for (i = 0; i < intf->cur_altsetting->desc.bNumEndpoints; i++) {
		ep_desc = &intf->cur_altsetting->endpoint[i].desc;

		if (!data->intr_ep && usb_endpoint_is_int_in(ep_desc)) {
			data->intr_ep = ep_desc;
			continue;
		}

		if (!data->bulk_tx_ep && usb_endpoint_is_bulk_out(ep_desc)) {
			data->bulk_tx_ep = ep_desc;
			continue;
		}

		if (!data->bulk_rx_ep && usb_endpoint_is_bulk_in(ep_desc)) {
			data->bulk_rx_ep = ep_desc;
			continue;
		}
	}

	if (!data->intr_ep || !data->bulk_tx_ep || !data->bulk_rx_ep) {
		pr_err("btmtk_usb_mt6639: Required endpoints not found\n");
		return -ENODEV;
	}

	pr_info("btmtk_usb_mt6639: Endpoints - INT: 0x%02x, BULK_TX: 0x%02x, BULK_RX: 0x%02x\n",
		data->intr_ep->bEndpointAddress,
		data->bulk_tx_ep->bEndpointAddress,
		data->bulk_rx_ep->bEndpointAddress);

	/* Create HCI device */
	hdev = hci_alloc_dev();
	if (!hdev)
		return -ENOMEM;

	data->hdev = hdev;

	hdev->bus = HCI_USB;
	hci_set_drvdata(hdev, data);

	/* Set device information */
	SET_HCIDEV_DEV(hdev, &intf->dev);

	/* Set callbacks */
	hdev->open = btmtk_open;
	hdev->close = btmtk_close;
	hdev->flush = btmtk_flush;
	hdev->send = btmtk_send_frame;
	hdev->setup = btmtk_setup;
	hdev->shutdown = btmtk_shutdown;

	usb_set_intfdata(intf, data);

	/* Register HCI device */
	err = hci_register_dev(hdev);
	if (err < 0) {
		bt_dev_err(hdev, "Failed to register HCI device: %d", err);
		hci_free_dev(hdev);
		return err;
	}

	bt_dev_info(hdev, "MediaTek MT6639 USB driver loaded");

	return 0;
}

static void btmtk_disconnect(struct usb_interface *intf)
{
	struct btmtk_data *data = usb_get_intfdata(intf);
	struct hci_dev *hdev = data->hdev;

	bt_dev_info(hdev, "Disconnecting MT6639 device");

	hci_unregister_dev(hdev);
	hci_free_dev(hdev);

	usb_kill_anchored_urbs(&data->tx_anchor);
	usb_kill_anchored_urbs(&data->intr_anchor);
	usb_kill_anchored_urbs(&data->bulk_anchor);
	usb_kill_anchored_urbs(&data->isoc_anchor);
}

#ifdef CONFIG_PM
static int btmtk_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct btmtk_data *data = usb_get_intfdata(intf);

	usb_kill_anchored_urbs(&data->tx_anchor);

	return 0;
}

static int btmtk_resume(struct usb_interface *intf)
{
	return 0;
}
#endif

static struct usb_driver btmtk_driver = {
	.name		= "btmtk_usb_mt6639",
	.probe		= btmtk_probe,
	.disconnect	= btmtk_disconnect,
#ifdef CONFIG_PM
	.suspend	= btmtk_suspend,
	.resume		= btmtk_resume,
#endif
	.id_table	= btmtk_table,
	.supports_autosuspend = 1,
	.disable_hub_initiated_lpm = 1,
};

module_usb_driver(btmtk_driver);

MODULE_AUTHOR("Based on Windows driver reverse engineering");
MODULE_DESCRIPTION("MediaTek MT6639 Bluetooth USB Driver");
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(MT6639_FW_NAME);
