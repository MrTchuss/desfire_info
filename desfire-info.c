#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

#include <stdarg.h>

int bf = 0;

static
int printkv(int indent, const char *key, const char *val, ...)
{
	va_list arglist;
	char format[BUFSIZ];
	char format1[BUFSIZ];
	int wcount;

	sprintf(format1, "%*s%s:%n", indent*4, "", key, &wcount);
	sprintf(format, "%s%*s%s\n", format1, 60-wcount, "", val);

	va_start(arglist, val);
	vprintf(format, arglist);
	va_end(arglist);
	return 0;
}

static
int try_default_keys(FreefareTag tag, uint8_t key_count)
{
	uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	MifareDESFireKey key_null  = mifare_desfire_des_key_new_with_version(key_data_null);

	uint8_t key_3des_default[16] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  };
	MifareDESFireKey key_3des = mifare_desfire_3des_key_new(key_3des_default);

	uint8_t key_3k3des_default[24] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  };
	MifareDESFireKey key_3k3des = mifare_desfire_3k3des_key_new(key_3k3des_default);

	uint8_t key_aes_default[16] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  };
	MifareDESFireKey key_aes = mifare_desfire_aes_key_new(key_aes_default);

	for (uint8_t i = 0; i < key_count; ++ i) {
		int res = mifare_desfire_authenticate(tag, i, key_null);
		printkv(3, "Default DES authentication for key %u", "%s", i, (res<0)?"failed":"succeeded");
		res = mifare_desfire_authenticate(tag, i, key_3des);
		printkv(3, "Default 3DES authentication for key %u", "%s", i, (res<0)?"failed":"succeeded");
		res = mifare_desfire_authenticate(tag, i, key_3k3des);
		printkv(3, "Default 3k3DES authentication for key %u", "%s", i, (res<0)?"failed":"succeeded");
		res = mifare_desfire_authenticate(tag, i, key_aes);
		printkv(3, "Default AES authentication for key %u", "%s", i, (res<0)?"failed":"succeeded");
	}
	mifare_desfire_key_free(key_null);
	mifare_desfire_key_free(key_3des);
	mifare_desfire_key_free(key_3k3des);
	mifare_desfire_key_free(key_aes);
	return 0;
}

static
int display_key_settings(FreefareTag tag)
{
	uint8_t settings;
	uint8_t max_keys;
	int res;
	uint8_t version;

	mifare_desfire_get_key_version(tag, 0, &version);
	printkv(1, "Master Key version", "%d (0x%02x)", version, version);

	res = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
	if (res == 0) {
		printkv(1, "Master Key settings", " ");
		printkv(2, "configuration changeable", "%s", (settings & 0x08)?"yes":"no");
		printkv(2, "Master Key required for create / delete", "%s", (settings & 0x04)?"no":"yes");
		printkv(2, "Free directory list access without Master Key", "%s", (settings & 0x02)?"yes":"no");
		printkv(2, "Allow changing the Master Key", "%s", (settings & 0x01)?"yes":"no");
		printkv(2, "key count", "%u", max_keys);
		if (bf == 1)
			try_default_keys(tag, max_keys);
	} else if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
		printkv(1, "Master Key settings", "LOCKED");
	} else {
		freefare_perror(tag, "mifare_desfire_get_key_settings");
		return -1;
	}

	uint32_t size;
	res = mifare_desfire_free_mem(tag, &size);
	/*printf("Free memory: ");
	if (0 == res) {
		printf("%d bytes\n", size);
	} else {
		printf("unknown\n");
	}*/
	return 0;
}

static
const char *MDFT_FILE_TYPES[] = {
    "standard data file",
    "backup data file",
    "value file with backup",
    "linear record file with backup",
    "cyclic record file with backup"
};

static
int display_file_settings(FreefareTag tag, uint8_t file_no)
{
	struct mifare_desfire_file_settings settings;
	uint8_t keynum;
	uint8_t keyvers;

	if (mifare_desfire_get_file_settings(tag, file_no, &settings) == -1) {
		warnx("Can't get file settings.");
		return -1;
	}

	printkv(1, "File number", "%u", file_no);

	printkv(2, "FileType", "%s", MDFT_FILE_TYPES[settings.file_type]);

	/*
	mifare_desfire_file_settings & 0x1 == 0 -> plain;
	mifare_desfire_file_settings == 0x01 => plain communication with macing
	mifare_desfire_file_settings == 0x03 fully enciphered communication
	*/
	char *commset;
	switch (settings.communication_settings) {
	case 0x01:
		commset = "Plain with MACing";
		break;
	case 0x03:
		commset = "Fully enciphered";
		break;
	default:
		commset = "Plain";
	}
	printkv(2, "Communication settings", "%s", commset);

	printkv(2, "Access rights", " ");

	keynum = (settings.access_rights & 0xF000) >> 12;
	if (mifare_desfire_get_key_version(tag, keynum, &keyvers)) {
		warnx("Can't get key version for key %u.", keynum);
		return -1;
	}
	printkv(3, "Read", "%u (vers: %u)", keynum, keyvers);

	keynum = (settings.access_rights & 0x0F00) >> 8;
	if (mifare_desfire_get_key_version(tag, keynum, &keyvers)) {
		warnx("Can't get key version for key %u.", keynum);
		return -1;
	}
	printkv(3, "Write", "%u (vers: %u)", keynum, keyvers);

	keynum = (settings.access_rights & 0x00F0) >> 4;
	if (mifare_desfire_get_key_version(tag, keynum, &keyvers)) {
		warnx("Can't get key version for key %u.", keynum);
		return -1;
	}
	printkv(3, "Read&Write", "%u (vers: %u)", keynum, keyvers);

	keynum = settings.access_rights & 0x000F;
	if (mifare_desfire_get_key_version(tag, keynum, &keyvers) == -1) {
		warnx("Can't get key version for key %u.", keynum);
		return -1;
	}
	if (keynum == 0x0E)
		printkv(3, "Change access right", "free");
	else if (keynum == 0x0F)
		printkv(3, "Change access right", "no access");
	else
		printkv(3, "Change access right", "%u (vers: %u)", keynum, keyvers);

	switch (settings.file_type) {
		case MDFT_STANDARD_DATA_FILE:
		case MDFT_BACKUP_DATA_FILE:
			printkv(2, "File size", "%x", settings.settings.standard_file.file_size);
			break;
		case MDFT_VALUE_FILE_WITH_BACKUP:
			printkv(2, "Lower Limit", "%x", settings.settings.value_file.lower_limit);
			printkv(2, "Upper Limit", "%x", settings.settings.value_file.upper_limit);
			printkv(2, "Limited Credit Value", "%x", settings.settings.value_file.limited_credit_value);
			printkv(2, "Limited Credit Enabled", "%x", settings.settings.value_file.limited_credit_enabled);
			break;
		case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
		case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
			printkv(2, "Record size", "%x", settings.settings.linear_record_file.record_size);
			printkv(2, "Max number of records", "%x", settings.settings.linear_record_file.max_number_of_records);
			printkv(2, "Current num of records", "%x", settings.settings.linear_record_file.current_number_of_records);
			break;
	}
	return 0;
}


int main(int argc, char *argv[])
{
	int error = EXIT_SUCCESS;
	nfc_device *device = NULL;
	FreefareTag *tags = NULL;

	if (argc == 2 && strcmp(argv[1], "--brute-force") == 0)
		bf = 1;
	else if (argc > 1)
		errx(EXIT_FAILURE, "usage: %s [--brute-force]", argv[0]);

	nfc_connstring devices[8];
	size_t device_count;

	nfc_context *context;
	nfc_init(&context);
	if (context == NULL)
		errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

	device_count = nfc_list_devices(context, devices, 8);
	if (device_count <= 0)
		errx(EXIT_FAILURE, "No NFC device found.");

	for (size_t d = 0; d < device_count; d++) {
		device = nfc_open(context, devices[d]);
		if (!device) {
			warnx("nfc_open() failed.");
			error = EXIT_FAILURE;
			continue;
		}

		tags = freefare_get_tags(device);
		if (!tags) {
			nfc_close(device);
			errx(EXIT_FAILURE, "Error listing tags.");
		}

		for (int i = 0; (!error) && tags[i]; i++) {
			if (MIFARE_DESFIRE != freefare_get_tag_type(tags[i]))
				continue;

			int res;
			char *tag_uid = freefare_get_tag_uid(tags[i]);

			struct mifare_desfire_version_info info;

			if (mifare_desfire_connect(tags[i]) == -1) {
				warnx ("Can't connect to Mifare DESFire target.");
				error = 1;
				break;
			}

			if (mifare_desfire_get_version(tags[i], &info) == -1) {
				freefare_perror(tags[i], "mifare_desfire_get_version");
				error = 1;
				break;
			}

			printf("================================================================================\n");
			printkv(0, "Version information for tag", "%s", tag_uid);
			printkv(0, "UID", "0x%02x%02x%02x%02x%02x%02x%02x", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
			printkv(0, "Batch number", "0x%02x%02x%02x%02x%02x", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
			printkv(0, "Production date", "week %x, 20%02x", info.production_week, info.production_year);
			printkv(0, "Hardware Information", " ");
			printkv(1, "Vendor ID", "0x%02x", info.hardware.vendor_id);
			printkv(1, "Type", "0x%02x", info.hardware.type);
			printkv(1, "Subtype", "0x%02x", info.hardware.subtype);
			printkv(1, "Version", "%d.%d", info.hardware.version_major, info.hardware.version_minor);
			printkv(1, "Storage size", "0x%02x (%s%d bytes)", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", 1 << (info.hardware.storage_size >> 1));
			printkv(1, "Protocol", "0x%02x", info.hardware.protocol);
			printkv(0, "Software Information", " ");
			printkv(1, "Vendor ID", "0x%02x", info.software.vendor_id);
			printkv(1, "Type", "0x%02x", info.software.type);
			printkv(1, "Subtype", "0x%02x", info.software.subtype);
			printkv(1, "Version", "%d.%d", info.software.version_major, info.software.version_minor);
			printkv(1, "Storage size", "0x%02x (%s%d bytes)", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", 1 << (info.software.storage_size >> 1));
			printkv(1, "Protocol", "0x%02x", info.software.protocol);
			printkv(0, "Use random UID", "%s", (strlen(tag_uid) / 2 == 4) ? "yes" : "no");


			printf("================================================================================\n");
			printkv(0, "Application", "00");
			if (display_key_settings(tags[i]) == -1) {
				error = 1;
				break;
			}

			MifareDESFireAID *aids;
			size_t applications_count;

			if (mifare_desfire_get_application_ids(tags[i], &aids, &applications_count) == -1) {
				warnx ("Can't get AIDS.");
				goto applications_ids_end;
			}
			for (size_t j = 0; j < applications_count; ++j) {
				printf("================================================================================\n");
				uint32_t aid = mifare_desfire_aid_get_aid(aids[j]);

				printkv(0, "Application", "%x", aid);
				if ((res = mifare_desfire_select_application(tags[i], aids[j])) < 0) {
					warnx("Can't select application %x.", aid);
					continue;
				}
				if (display_key_settings(tags[i]) == -1) {
					error = 1;
					break;
				}

				uint8_t *files;
				size_t file_count;

				if (mifare_desfire_get_file_ids(tags[i], &files, &file_count) == -1) {
					warnx("Cannot get file IDs for application %x.", aid);
				}
				printkv(1, "File count", "%u", file_count);
				for (size_t k = 0; k < file_count; ++k) {
					display_file_settings(tags[i], k);
				}
				free(files);
			}

applications_ids_end:
			mifare_desfire_free_application_ids(aids);

			free(tag_uid);

			mifare_desfire_disconnect(tags[i]);
		}

		freefare_free_tags(tags);
		nfc_close(device);
	}
	nfc_exit(context);
	exit(error);
}				/* main() */
