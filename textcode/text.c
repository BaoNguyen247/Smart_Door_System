static esp_err_t read_write(rc522_handle_t scanner, rc522_picc_t *picc)
{
    const char *data_to_write = "Smartlock best";
    const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    if (strlen(data_to_write) > 16) {
        ESP_LOGW(TAGRC522, "Password length must not exceed 16 characters");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_RETURN_ON_ERROR(rc522_mifare_auth(scanner, picc, block_address, &key), TAGRC522, "auth fail");

    uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];
    uint8_t write_buffer[RC522_MIFARE_BLOCK_SIZE] = {0};

    // Read
    ESP_LOGI(TAGRC522, "Reading data from the block %d", block_address);
    ESP_RETURN_ON_ERROR(rc522_mifare_read(scanner, picc, block_address, read_buffer), TAGRC522, "read fail");
    ESP_LOGI(TAGRC522, "Current data:");
    dump_block(read_buffer);
    // ~Read

    // Write
    strncpy((char *)write_buffer, data_to_write, RC522_MIFARE_BLOCK_SIZE);

    ESP_LOGI(TAGRC522, "Writing data (%s) to the block %d:", data_to_write, block_address);
    dump_block(write_buffer);
    ESP_RETURN_ON_ERROR(rc522_mifare_write(scanner, picc, block_address, write_buffer), TAGRC522, "write fail");
    // ~Write

    // Read again
    ESP_LOGI(TAGRC522, "Write done. Verifying...");
    ESP_RETURN_ON_ERROR(rc522_mifare_read(scanner, picc, block_address, read_buffer), TAGRC522, "read fail");
    ESP_LOGI(TAGRC522, "New data in the block %d:", block_address);
    dump_block(read_buffer);
    // ~Read again

    // Validate
    bool rw_missmatch = false;
    uint8_t i;
    for (i = 0; i < RC522_MIFARE_BLOCK_SIZE; i++) {
        if (write_buffer[i] != read_buffer[i]) {
            rw_missmatch = true;
            break;
        }
    }
    // ~Validate

    // Feedback
    if (!rw_missmatch) {
        ESP_LOGI(TAGRC522, "Verified.");
    }
    else {
        ESP_LOGE(TAGRC522,
            "Write failed. RW missmatch on the byte %d (w:%02" RC522_X ", r:%02" RC522_X ")",
            i,
            write_buffer[i],
            read_buffer[i]);

        dump_block(write_buffer);
        dump_block(read_buffer);
    }
    // ~Feedback

    return ESP_OK;
}


static void on_picc_state_changed(void *arg, esp_event_base_t base, int32_t event_id, void *data)
{
    rc522_picc_state_changed_event_t *event = (rc522_picc_state_changed_event_t *)data;
    rc522_picc_t *picc = event->picc;

    if (picc->state != RC522_PICC_STATE_ACTIVE) {
        return;
    }

    rc522_picc_print(picc);

    if (!rc522_mifare_type_is_classic_compatible(picc->type)) {
        ESP_LOGW(TAGRC522, "Card is not supported by this example");
        return;
    }

    if (read_write(scanner, picc) == ESP_OK) {
        ESP_LOGI(TAGRC522, "Read/Write success");
    }
    else {
        ESP_LOGE(TAGRC522, "Read/Write failed");
    }

    if (rc522_mifare_deauth(scanner, picc) != ESP_OK) {
        ESP_LOGW(TAGRC522, "Deauth failed");
    }
}

// Hàm lưu mật khẩu vào NVS
static esp_err_t save_password_to_nvs(const char *password, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return err;
    }
    err = nvs_set_blob(nvs_handle, "doorpassword", password, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write password to NVS: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS changes: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "Saved password to NVS: %.*s", (int)len, password);
    return ESP_OK;
}
// Hàm đọc mật khẩu từ NVS
static esp_err_t load_password_from_nvs(char *password, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return err;
    }
    size_t required_size;
    err = nvs_get_blob(nvs_handle, "doorpassword", NULL, &required_size);
    if (err != ESP_OK || required_size != len) {
        ESP_LOGE(TAG, "Failed to get password size from NVS or size mismatch: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    err = nvs_get_blob(nvs_handle, "doorpassword", password, &required_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read password from NVS: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "Loaded password from NVS: %.*s", (int)len, password);
    return ESP_OK;
}


static esp_err_t write_pass(rc522_handle_t scanner, rc522_picc_t *picc)
{
    const char *data_to_write = "rc522 is dope";
    const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    if (strlen(data_to_write) > 16) {
        ESP_LOGW(TAGRC522, "Password length must not exceed 16 characters");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_RETURN_ON_ERROR(rc522_mifare_auth(scanner, picc, block_address, &key), TAGRC522, "auth fail");

    uint8_t write_buffer[RC522_MIFARE_BLOCK_SIZE] = {0};
    strncpy((char *)write_buffer, data_to_write, RC522_MIFARE_BLOCK_SIZE);

    ESP_LOGI(TAGRC522, "Writing fixed password (%s) to block %d:", data_to_write, block_address);
    ESP_RETURN_ON_ERROR(rc522_mifare_write(scanner, picc, block_address, write_buffer), TAGRC522, "write fail");

    return ESP_OK;
}





















static esp_err_t read_pass(rc522_handle_t scanner, rc522_picc_t *picc)
{
    const char *data_to_write = "rc522 is dope";
    const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    if (strlen(data_to_write) > 14) {
        ESP_LOGW(TAGRC522, "Please make sure that data length is no more than 14 characters");
        ESP_LOGW(TAGRC522, "since we are going to use random values for last two bytes");

        return ESP_ERR_INVALID_ARG;
    }

    ESP_RETURN_ON_ERROR(rc522_mifare_auth(scanner, picc, block_address, &key), TAGRC522, "auth fail");

    uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];
    uint8_t write_buffer[RC522_MIFARE_BLOCK_SIZE];

    // Read
    ESP_LOGI(TAGRC522, "Reading data from the block %d", block_address);
    ESP_RETURN_ON_ERROR(rc522_mifare_read(scanner, picc, block_address, read_buffer), TAGRC522, "read fail");
    ESP_LOGI(TAGRC522, "Current data:");
    dump_block(read_buffer);
    // ~Read

    // Write
    strncpy((char *)write_buffer, data_to_write, RC522_MIFARE_BLOCK_SIZE);

    // Set random values for the last two bytes in the write buffer
    // so we are using new data on each call of read_write function
    int r = rand();
    write_buffer[RC522_MIFARE_BLOCK_SIZE - 2] = ((r >> 8) & 0xFF);
    write_buffer[RC522_MIFARE_BLOCK_SIZE - 1] = ((r >> 0) & 0xFF);

    ESP_LOGI(TAGRC522, "Writing data (%s) to the block %d:", data_to_write, block_address);
    dump_block(write_buffer);
    ESP_RETURN_ON_ERROR(rc522_mifare_write(scanner, picc, block_address, write_buffer), TAGRC522, "write fail");
    // ~Write

    // Read again
    ESP_LOGI(TAGRC522, "Write done. Verifying...");
    ESP_RETURN_ON_ERROR(rc522_mifare_read(scanner, picc, block_address, read_buffer), TAGRC522, "read fail");
    ESP_LOGI(TAGRC522, "New data in the block %d:", block_address);
    dump_block(read_buffer);
    // ~Read again

    // Validate
    bool rw_missmatch = false;
    uint8_t i;
    for (i = 0; i < RC522_MIFARE_BLOCK_SIZE; i++) {
        if (write_buffer[i] != read_buffer[i]) {
            rw_missmatch = true;
            break;
        }
    }
    // ~Validate

    // Feedback
    if (!rw_missmatch) {
        ESP_LOGI(TAGRC522, "Verified.");
    }
    else {
        ESP_LOGE(TAGRC522,
            "Write failed. RW missmatch on the byte %d (w:%02" RC522_X ", r:%02" RC522_X ")",
            i,
            write_buffer[i],
            read_buffer[i]);

        dump_block(write_buffer);
        dump_block(read_buffer);
    }
    // ~Feedback

    return ESP_OK;
}



static esp_err_t read_pass(rc522_handle_t scanner, rc522_picc_t *picc)
{
    const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    ESP_RETURN_ON_ERROR(rc522_mifare_auth(scanner, picc, block_address, &key), TAGRC522, "auth fail");

    uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];
    ESP_LOGI(TAGRC522, "Reading password from block %d", block_address);
    ESP_RETURN_ON_ERROR(rc522_mifare_read(scanner, picc, block_address, read_buffer), TAGRC522, "read fail");
    ESP_LOGI(TAGRC522, "Password data:");
    dump_block(read_buffer);

    return ESP_OK;
}




static bool check_pass(rc522_handle_t scanner, rc522_picc_t *picc)
{
    const char *expected_pass = "rc522 is dope";
    const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    ESP_RETURN_ON_FALSE(!rc522_mifare_auth(scanner, picc, block_address, &key), false, TAGRC522, "auth fail");

    uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];
    ESP_LOGI(TAGRC522, "Reading password from block %d", block_address);
    ESP_RETURN_ON_FALSE(!rc522_mifare_read(scanner, picc, block_address, read_buffer), false, TAGRC522, "read fail");

    // Compare read data with expected password
    bool match = strncmp((char *)read_buffer, expected_pass, strlen(expected_pass)) == 0;
    ESP_LOGI(TAGRC522, "Password match: %s", match ? "true" : "false");

    return match;
}