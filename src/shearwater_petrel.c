/*
 * libdivecomputer
 *
 * Copyright (C) 2013 Jef Driesen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <string.h> // memcmp, memcpy
#include <stdlib.h> // malloc, free

#include "shearwater_petrel.h"
#include "shearwater_common.h"
#include "context-private.h"
#include "device-private.h"
#include "platform.h"
#include "array.h"

#define ISINSTANCE(device) dc_device_isinstance((device), &shearwater_petrel_device_vtable)

#define MANIFEST_ADDR 0xE0000000
#define MANIFEST_SIZE 0x600

#define DIVE_SIZE     0xFFFFFF

#define RECORD_SIZE   0x20

// Attempts per dive download (initial + retries) and the pre-retry delay
// (ms), mirroring the hw_ostc3 BLE retry rationale (issues #394, #759).
#define SHEARWATER_DIVE_ATTEMPTS 3
#define SHEARWATER_RETRY_DELAY 300
#define RECORD_COUNT  (MANIFEST_SIZE / RECORD_SIZE)

typedef struct shearwater_petrel_device_t {
	shearwater_common_device_t base;
	unsigned char fingerprint[4];
} shearwater_petrel_device_t;

static dc_status_t shearwater_petrel_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size);
static dc_status_t shearwater_petrel_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata);
static dc_status_t shearwater_petrel_device_timesync (dc_device_t *abstract, const dc_datetime_t *datetime);
static dc_status_t shearwater_petrel_device_close (dc_device_t *abstract);

static const dc_device_vtable_t shearwater_petrel_device_vtable = {
	sizeof(shearwater_petrel_device_t),
	DC_FAMILY_SHEARWATER_PETREL,
	shearwater_petrel_device_set_fingerprint, /* set_fingerprint */
	NULL, /* read */
	NULL, /* write */
	NULL, /* dump */
	shearwater_petrel_device_foreach, /* foreach */
	shearwater_petrel_device_timesync,
	shearwater_petrel_device_close /* close */
};


static unsigned int
str2num (unsigned char data[], unsigned int size, unsigned int offset)
{
	unsigned int value = 0;
	for (unsigned int i = offset; i < size; ++i) {
		if (data[i] < '0' || data[i] > '9')
			break;
		value *= 10;
		value += data[i] - '0';
	}

	return value;
}


dc_status_t
shearwater_petrel_device_open (dc_device_t **out, dc_context_t *context, dc_iostream_t *iostream, unsigned int model)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	shearwater_petrel_device_t *device = NULL;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	// Allocate memory.
	device = (shearwater_petrel_device_t *) dc_device_allocate (context, &shearwater_petrel_device_vtable);
	if (device == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	// Set the default values.
	memset (device->fingerprint, 0, sizeof (device->fingerprint));

	// Setup the device.
	status = shearwater_common_setup (&device->base, context, iostream, model);
	if (status != DC_STATUS_SUCCESS) {
		goto error_free;
	}

	*out = (dc_device_t *) device;

	return DC_STATUS_SUCCESS;

error_free:
	dc_device_deallocate ((dc_device_t *) device);
	return status;
}


static dc_status_t
shearwater_petrel_device_close (dc_device_t *abstract)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	shearwater_common_device_t *device = (shearwater_common_device_t *) abstract;
	dc_status_t rc = DC_STATUS_SUCCESS;

	// Shutdown the device.
	unsigned char request[] = {0x2E, 0x90, 0x20, 0x00};
	rc = shearwater_common_transfer (device, request, sizeof (request), NULL, 0, NULL);
	if (rc != DC_STATUS_SUCCESS) {
		dc_status_set_error(&status, rc);
	}

	return status;
}


static dc_status_t
shearwater_petrel_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size)
{
	shearwater_petrel_device_t *device = (shearwater_petrel_device_t *) abstract;

	if (size && size != sizeof (device->fingerprint))
		return DC_STATUS_INVALIDARGS;

	if (size)
		memcpy (device->fingerprint, data, sizeof (device->fingerprint));
	else
		memset (device->fingerprint, 0, sizeof (device->fingerprint));

	return DC_STATUS_SUCCESS;
}


static dc_status_t
shearwater_petrel_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata)
{
	shearwater_petrel_device_t *device = (shearwater_petrel_device_t *) abstract;
	dc_status_t rc = DC_STATUS_SUCCESS;

	// Enable progress notifications.
	unsigned int current = 0, maximum = 0;
	dc_event_progress_t progress = EVENT_PROGRESS_INITIALIZER;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// Read the serial number.
	unsigned char rsp_serial[8] = {0};
	rc = shearwater_common_rdbi (&device->base, ID_SERIAL, rsp_serial, sizeof(rsp_serial), NULL);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the serial number.");
		return rc;
	}

	HEXDUMP(abstract->context, DC_LOGLEVEL_DEBUG, "Serial", rsp_serial, sizeof(rsp_serial));

	// Convert to a number.
	unsigned char serial[4] = {0};
	if (array_convert_hex2bin (rsp_serial, sizeof(rsp_serial), serial, sizeof (serial)) != 0 ) {
		ERROR (abstract->context, "Failed to convert the serial number.");
		return DC_STATUS_DATAFORMAT;
	}

	// Read the firmware version.
	unsigned char rsp_firmware[12] = {0};
	unsigned int rsp_firmware_length = 0;
	rc = shearwater_common_rdbi (&device->base, ID_FIRMWARE, rsp_firmware, sizeof(rsp_firmware), &rsp_firmware_length);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the firmware version.");
		return rc;
	}

	HEXDUMP(abstract->context, DC_LOGLEVEL_DEBUG, "Firmware", rsp_firmware, rsp_firmware_length);

	// Convert to a number.
	unsigned int firmware = str2num (rsp_firmware, rsp_firmware_length, 1);

	// Read the model number.
	unsigned char model = 0;
	rc = shearwater_common_rdbi (&device->base, ID_MODEL, &model, sizeof(model), NULL);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the model number.");
		return rc;
	}

	HEXDUMP(abstract->context, DC_LOGLEVEL_DEBUG, "Model", &model, sizeof(model));

	// Emit a device info event.
	dc_event_devinfo_t devinfo;
	devinfo.model = model;
	devinfo.firmware = firmware;
	devinfo.serial = array_uint32_be (serial);
	device_event_emit (abstract, DC_EVENT_DEVINFO, &devinfo);

	// Read the logbook type
	unsigned char rsp_logupload[9] = {0};
	rc = shearwater_common_rdbi (&device->base, ID_LOGUPLOAD, rsp_logupload, sizeof(rsp_logupload), NULL);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the logbook type.");
		return rc;
	}

	unsigned int base_addr = array_uint32_be (rsp_logupload + 1);
	switch (base_addr) {
	case 0xDD000000: // Predator - we shouldn't get here, we could give up or we can try 0xC0000000
	case 0xC0000000: // Predator-Like Format (what we used to call the Petrel format)
	case 0x90000000: // some firmware versions supported an earlier version of PNF without final record
		// use the Predator-Like Format instead
		base_addr = 0xC0000000;
		break;
	case 0x80000000: // new Petrel Native Format with final record
		// that's the correct address
		break;
	default: // unknown format
		ERROR (abstract->context, "Unknown logbook format %08x", base_addr);
		return DC_STATUS_DATAFORMAT;
	}

	// Allocate memory buffers for the manifests.
	dc_buffer_t *buffer = dc_buffer_new (MANIFEST_SIZE);
	dc_buffer_t *manifests = dc_buffer_new (MANIFEST_SIZE);
	if (buffer == NULL || manifests == NULL) {
		ERROR (abstract->context, "Insufficient buffer space available.");
		dc_buffer_free (buffer);
		dc_buffer_free (manifests);
		return DC_STATUS_NOMEMORY;
	}

	// True if the manifest walk found an exact fingerprint match. An
	// unmatched non-zero fingerprint is treated as a timestamp floor (see
	// below); an exact match keeps the historical truncate-at-match
	// behavior untouched, so the floor logic must stay inert.
	unsigned int found = 0;

	// Read the manifest pages
	while (1) {
		// Update the progress state.
		// Assume the worst case scenario of a full manifest, and adjust the
		// value with the actual number of dives after the manifest has been
		// processed.
		maximum += 1 + RECORD_COUNT;

		// Download a manifest.
		progress.current = NSTEPS * current;
		progress.maximum = NSTEPS * maximum;
		rc = shearwater_common_download (&device->base, buffer, MANIFEST_ADDR, MANIFEST_SIZE, 0, &progress);
		if (rc != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to download the manifest.");
			dc_buffer_free (buffer);
			dc_buffer_free (manifests);
			return rc;
		}

		HEXDUMP(abstract->context, DC_LOGLEVEL_DEBUG, "Manifest", dc_buffer_get_data (buffer), dc_buffer_get_size (buffer));

		// Cache the buffer pointer and size.
		unsigned char *data = dc_buffer_get_data (buffer);
		unsigned int size = dc_buffer_get_size (buffer);

		// Process the records in the manifest.
		unsigned int count = 0, deleted = 0;
		unsigned int offset = 0;
		while (offset < size) {
			// Check for a valid dive header.
			unsigned int header = array_uint16_be (data + offset);
			if (header == 0x5A23) {
				// this is a deleted dive; keep looking
				offset += RECORD_SIZE;
				deleted++;
				continue;
			}
			if (header != 0xA5C4)
				break;

			// Check the fingerprint data.
			if (memcmp (data + offset + 4, device->fingerprint, sizeof (device->fingerprint)) == 0) {
				found = 1;
				break;
			}

			offset += RECORD_SIZE;
			count++;
		}

		// Update the progress state. Deleted records are never
		// downloaded, so they must not count towards the maximum.
		current += 1;
		maximum -= RECORD_COUNT - count;

		// Append all walked records to the main buffer, including the
		// deleted ones. The walk advances past deleted records without
		// counting them, so appending only a count-sized prefix would
		// push any valid record behind a deleted one past the appended
		// bytes, and its dive would silently never be downloaded. The
		// dive download loop skips the deleted records.
		if (!dc_buffer_append (manifests, data, offset)) {
			ERROR (abstract->context, "Insufficient buffer space available.");
			dc_buffer_free (buffer);
			dc_buffer_free (manifests);
			return DC_STATUS_NOMEMORY;
		}

		// Stop downloading manifest if there are no more records.
		if (count + deleted != RECORD_COUNT)
			break;
	}

	// Cache the buffer pointer and size.
	unsigned char *data = dc_buffer_get_data (manifests);
	unsigned int size = dc_buffer_get_size (manifests);

	// A fingerprint that matched no manifest record is treated as a
	// timestamp floor: the petrel fingerprint is the dive start time
	// (big-endian ticks, mirrored at record offset 4), so records at or
	// before the floor are skipped without issuing their download request.
	// An exact match (found) keeps the historical behavior untouched.
	unsigned int floor_ticks = 0;
	if (!found)
		floor_ticks = array_uint32_be (device->fingerprint);
	if (floor_ticks) {
		unsigned int nrecords = size / RECORD_SIZE;
		for (unsigned int i = 0; i < nrecords; ++i) {
			unsigned int offset = i * RECORD_SIZE;
			if (array_uint16_be (data + offset) == 0x5A23)
				continue;
			if (array_uint32_be (data + offset + 4) <= floor_ticks)
				maximum -= 1;
		}
	}

	// Update and emit a progress event.
	progress.current = NSTEPS * current;
	progress.maximum = NSTEPS * maximum;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// The manifest records are ordered newest to oldest. Walk them in
	// reverse, so the dives are delivered oldest to newest. The download
	// stops at the first failure, so a partial download always leaves a
	// contiguous prefix of the oldest dives, and the newest delivered dive
	// remains a correct fingerprint to resume from on the next attempt.
	unsigned int nrecords = size / RECORD_SIZE;
	unsigned int delivered = 0;
	for (unsigned int i = nrecords; i > 0; --i) {
		unsigned int offset = (i - 1) * RECORD_SIZE;

		// skip deleted dives
		if (array_uint16_be(data + offset) == 0x5A23) {
			continue;
		}

		// Skip dives at or before the timestamp floor.
		if (floor_ticks && array_uint32_be (data + offset + 4) <= floor_ticks)
			continue;

		// Get the address of the dive.
		unsigned int address = array_uint32_be (data + offset + 20);

		// Download the dive, retrying transient link errors (issue #759).
		// One lost BLE notification used to abort the entire pass, and
		// with the oldest-first order that failure struck before ANY dive
		// had been delivered, so the app reported "Download failed" with
		// zero dives and no partial-import offer. Mirrors the hw_ostc3
		// download retry (issue #394).
		rc = DC_STATUS_SUCCESS;
		for (unsigned int attempt = 0; attempt < SHEARWATER_DIVE_ATTEMPTS; ++attempt) {
			progress.current = NSTEPS * current;
			progress.maximum = NSTEPS * maximum;
			rc = shearwater_common_download (&device->base, buffer, base_addr + address, DIVE_SIZE, 1, &progress);
			if (rc == DC_STATUS_SUCCESS)
				break;
			if (rc == DC_STATUS_CANCELLED || device_is_cancelled (abstract)) {
				rc = DC_STATUS_CANCELLED;
				break;
			}
			// Only re-issue on a transient link error; anything else is
			// deterministic and would only fail again.
			if (rc != DC_STATUS_TIMEOUT && rc != DC_STATUS_IO && rc != DC_STATUS_PROTOCOL)
				break;
			if (attempt + 1 < SHEARWATER_DIVE_ATTEMPTS) {
				WARNING (abstract->context,
					"Dive download failed (status %d); retrying (%u/%u).",
					rc, attempt + 2, SHEARWATER_DIVE_ATTEMPTS);
				dc_iostream_sleep (device->base.iostream, SHEARWATER_RETRY_DELAY);
				dc_iostream_purge (device->base.iostream, DC_DIRECTION_ALL);
			}
		}
		if (rc != DC_STATUS_SUCCESS) {
			if (rc != DC_STATUS_CANCELLED && delivered > 0) {
				// Persistent failure mid-pass: keep what was delivered
				// instead of reporting a total failure. The oldest-first
				// contract holds -- the delivered dives are a contiguous
				// oldest prefix and the newest delivered fingerprint is a
				// valid resume point for the next attempt (#759).
				WARNING (abstract->context,
					"Keeping %u downloaded dives after a persistent failure.",
					delivered);
				maximum = current;
				rc = DC_STATUS_SUCCESS;
				break;
			}
			ERROR (abstract->context, "Failed to download the dive.");
			dc_buffer_free (buffer);
			dc_buffer_free (manifests);
			return rc;
		}

		// Update the progress state.
		current += 1;
		delivered += 1;

		unsigned char *buf = dc_buffer_get_data (buffer);
		unsigned int len = dc_buffer_get_size (buffer);
		if (callback && !callback (buf, len, buf + 12, sizeof (device->fingerprint), userdata))
			break;
	}

	// Update and emit a progress event.
	progress.current = NSTEPS * current;
	progress.maximum = NSTEPS * maximum;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	dc_buffer_free (manifests);
	dc_buffer_free (buffer);

	return rc;
}

static dc_status_t
shearwater_petrel_device_timesync (dc_device_t *abstract, const dc_datetime_t *datetime)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	shearwater_common_device_t *device = (shearwater_common_device_t *) abstract;

	// Read the model number.
	unsigned char model = 0;
	status = shearwater_common_rdbi (device, ID_MODEL, &model, sizeof(model), NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the model number.");
		return status;
	}

	if (model == TERIC) {
		return shearwater_common_timesync_utc (device, datetime);
	} else {
		return shearwater_common_timesync_local (device, datetime);
	}
}
