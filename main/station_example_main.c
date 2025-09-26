#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/timers.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/i2c_master.h"
#include "mqtt_client.h"
#include <inttypes.h>
#include "nvs_flash.h"
#include "nvs.h"
#define CONFIG_ESP_WIFI_SSID "Redmi11"
#define CONFIG_ESP_WIFI_PASSWORD "24702470"

#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

#if CONFIG_ESP_STATION_EXAMPLE_WPA3_SAE_PWE_HUNT_AND_PECK
#define ESP_WIFI_SAE_MODE WPA3_SAE_PWE_HUNT_AND_PECK
#define EXAMPLE_H2E_IDENTIFIER ""
#elif CONFIG_ESP_STATION_EXAMPLE_WPA3_SAE_PWE_HASH_TO_ELEMENT
#define ESP_WIFI_SAE_MODE WPA3_SAE_PWE_HASH_TO_ELEMENT
#define EXAMPLE_H2E_IDENTIFIER CONFIG_ESP_WIFI_PW_ID
#elif CONFIG_ESP_STATION_EXAMPLE_WPA3_SAE_PWE_BOTH
#define ESP_WIFI_SAE_MODE WPA3_SAE_PWE_BOTH
#define EXAMPLE_H2E_IDENTIFIER CONFIG_ESP_WIFI_PW_ID
#endif
#if CONFIG_ESP_WIFI_AUTH_OPEN
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_ESP_WIFI_AUTH_WEP
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_ESP_WIFI_AUTH_WPA_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WAPI_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#endif
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
//GPIO for matrix keypad
#define GPIO_ROW_1 32
#define GPIO_ROW_2 33
#define GPIO_ROW_3 25
#define GPIO_ROW_4 26
#define GPIO_COL_1 27
#define GPIO_COL_2 14
#define GPIO_COL_3 12
#define GPIO_COL_4 13
#define GPIO_ROW_BIT_MASK (1ULL << GPIO_ROW_1) | (1ULL << GPIO_ROW_2) | (1ULL << GPIO_ROW_3) | (1ULL << GPIO_ROW_4)
#define GPIO_COL_BIT_MASK (1ULL << GPIO_COL_1) | (1ULL << GPIO_COL_2) | (1ULL << GPIO_COL_3) | (1ULL << GPIO_COL_4)
#define ESP_INTR_FLAG_DEFAULT 0
//END define for matrix keypad
static const char *TAG = "smartlock_application";
static const char *TAG1 = "matrix_keypad trigger";

static esp_mqtt_client_handle_t mqtt_client = NULL;
static QueueHandle_t matrix_interrupt_queue = NULL;
static TimerHandle_t debounce_timer = NULL;
static EventGroupHandle_t s_wifi_event_group;
static QueueHandle_t pass_input_buffer = NULL;



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

//Some global variables
char door_password[6] = {'1', '2', '3', '4', '5', '6'};
char door_password_buffer[6] = {'\0', '\0', '\0', '\0', '\0', '\0'};
uint8_t count_input = 0;
uint8_t number = 0; 
bool lock_state = true; //true is lock, false is unlock
 
// Keypad structure
typedef struct {
    gpio_num_t row_gpios[4];
    gpio_num_t col_gpios[4];
    uint32_t col_state[4]; // Track column states for debouncing
} matrix_keypad_t;

static matrix_keypad_t keypad = {
    .row_gpios = {GPIO_ROW_1, GPIO_ROW_2, GPIO_ROW_3, GPIO_ROW_4},
    .col_gpios = {GPIO_COL_1, GPIO_COL_2, GPIO_COL_3, GPIO_COL_4},
    .col_state = {0, 0, 0, 0} // Initially no keys pressed (all columns high)
};

// Key code macro
#define MAKE_KEY_CODE(row, col) ((row) * 4 + (col))
// Key mapping for 4x4 keypad (e.g., '1', '2', ..., '*', '#')
static const char key_map[4][4] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};

//END define for matrix keypad 

// ISR handler for column interrupts
static void IRAM_ATTR gpio_isr_handler(void *arg)
{
    matrix_keypad_t *keypad = (matrix_keypad_t *)arg;
    BaseType_t high_task_wakeup = pdFALSE;
    
    // Disable column interrupts
    for (int i = 0; i < 4; i++) {
        gpio_intr_disable(keypad->col_gpios[i]);
    }
    
    // Start debounce timer
    xTimerStartFromISR(debounce_timer, &high_task_wakeup);
    if (high_task_wakeup) {
        portYIELD_FROM_ISR();
    }
}

static void matrix_keypad_debounce_timer_callback(TimerHandle_t xTimer)
{
    matrix_keypad_t *keypad = (matrix_keypad_t *)pvTimerGetTimerID(xTimer);
    
    // Step 1: Scan columns to find which one is high
    int a = -1; // Store the index of the high column (-1 if none)
    for (int col = 0; col < 4; col++) {
        if (gpio_get_level(keypad->col_gpios[col]) == 1) {
            a = col; // Save the first high column
            break;   // Exit after finding the first high column
        }
    }
    
    // If no column is high, re-enable interrupts and return
    if (a == -1) {
        ESP_LOGI(TAG, "No column is high, skipping scan");
        goto reenable_interrupts;
    }
    
    // Debug: Log the high column
    ESP_LOGI(TAG, "Column detected on (GPIO %d)",keypad->col_gpios[a]);
    
    // Step 2: Scan each row to check if the high column goes low
    for (int row = 0; row < 4; row++) {
        // Drive current row low, others high
        for (int i = 0; i < 4; i++) {
            gpio_set_level(keypad->row_gpios[i], (i == row) ? 0 : 1);
        }
        
        // Small delay to stabilize GPIO levels
        vTaskDelay(2 / portTICK_PERIOD_MS);
        
        // Check if the high column (a) is now low
        if (gpio_get_level(keypad->col_gpios[a]) == 0) {
            uint32_t key_code = MAKE_KEY_CODE(row, a);
            char key = key_map[row][a];
            ESP_LOGI(TAG, "Key pressed: Row=%d, Col=%d, Code=%"PRIu32", Key=%c", row, a, key_code, key);
            xQueueSendFromISR(pass_input_buffer, &key, NULL);
        }
    }
    
    // Step 3: Restore rows to high
    for (int i = 0; i < 4; i++) {
        gpio_set_level(keypad->row_gpios[i], 1);
    }
    
    // Step 4: Re-enable column interrupts
    reenable_interrupts:
        for (int i = 0; i < 4; i++) {
            esp_err_t ret = gpio_intr_enable(keypad->col_gpios[i]);
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "Failed to re-enable interrupt for col %d: %s", keypad->col_gpios[i], esp_err_to_name(ret));
            }
        }
}

// Initialize the keypad
static esp_err_t matrix_keypad_init(matrix_keypad_t *keypad)
{
    esp_err_t ret;

    // Configure row GPIOs as outputs
    gpio_config_t row_conf = {
        .pin_bit_mask = GPIO_ROW_BIT_MASK,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    ret = gpio_config(&row_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Row config failed: %s", esp_err_to_name(ret));
        return ret;
    }

    // Configure column GPIOs as inputs with pull-ups and interrupts
    gpio_config_t col_conf = {
        .pin_bit_mask = GPIO_COL_BIT_MASK,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_POSEDGE
    };
    ret = gpio_config(&col_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Column config failed: %s", esp_err_to_name(ret));
        return ret;
    }

    // Initialize ISR service
    ret = gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to install ISR service: %s", esp_err_to_name(ret));
        return ret;
    }

    // Attach ISR handlers to column pins
    for (int i = 0; i < 4; i++) {
        ret = gpio_isr_handler_add(keypad->col_gpios[i], gpio_isr_handler, keypad);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to add ISR for col %d: %s", keypad->col_gpios[i], esp_err_to_name(ret));
            return ret;
        }
    }

    // Create debounce timer
    debounce_timer = xTimerCreate("keypad_debounce", pdMS_TO_TICKS(50), pdFALSE, keypad, 
                                  matrix_keypad_debounce_timer_callback);
    if (!debounce_timer) {
        ESP_LOGE(TAG, "Failed to create debounce timer");
        return ESP_FAIL;
    }

    // Set rows high initially
    for (int i = 0; i < 4; i++) {
        ret = gpio_set_level(keypad->row_gpios[i], 1);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set row %d high: %s", keypad->row_gpios[i], esp_err_to_name(ret));
            return ret;
        }
    }

    return ESP_OK;
}



static void password_check(void* arg)
{
    char key;
    for (;;) {
        if (xQueueReceive(pass_input_buffer, &key, portMAX_DELAY)) {
            printf("Check pass : %c\n", key);
            if(count_input <= 5) {
                door_password_buffer[count_input] = key;
                count_input++;
                if(count_input == 6){
                    count_input = 0;
                    bool result_check = true;
                    //Let check password
                    printf("Checking password...\n");
                    for (int i = 0; i < 6; i++){
                        if (door_password[i] != door_password_buffer[i]){
                            result_check = false;
                        }
                    }
                    if (result_check) {
                        printf("Correct password! Door unlocked.\n");
                        lock_state = false;
                    }else{
                        printf("Wrong password! Access denied.\n");
                        lock_state = true;
                    }
                    //Reset buffer
                    for(int i = 0; i < 6; i++){
                        door_password_buffer[i] = '\0';
                    }
                }
            }
        }
    }
}

static int s_retry_num = 0;
static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

static void mqtt_event_handler2(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_publish(client, "test1", "data_3", 0, 1, 0);
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_unsubscribe(client, "test1");
        ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);



        msg_id = esp_mqtt_client_subscribe(client, "test2", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_subscribe(client, "pass/update", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_subscribe(client, "door/control", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        // msg_id = esp_mqtt_client_subscribe(client, "test1", 1);
        // ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        msg_id = esp_mqtt_client_publish(client, "test1", "data", 0, 0, 0);
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        if (strncmp(event->topic, "pass/update", event->topic_len) == 0) {
            // Update door password
            if (event->data_len == 6) {
                memcpy(door_password, event->data, 6);
                ESP_LOGI(TAG, "Door password updated via MQTT");
            } else {
                ESP_LOGW(TAG, "Received invalid password length via MQTT");
            }
            esp_err_t ret;
            ret = save_password_to_nvs(door_password, sizeof(door_password));
                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to save default password to NVS");
                    return;
                }
        } else if (strncmp(event->topic, "door/control", event->topic_len) == 0) {
            // Control door lock state
            if (strncmp(event->data, "lock", event->data_len) == 0) {
                lock_state = true;
                for (int i = 0; i < 6; i++){
                    door_password_buffer[i] = '\0';
                }
                count_input = 0;
                ESP_LOGI(TAG, "Door locked via MQTT");
            } else if (strncmp(event->data, "unlock", event->data_len) == 0) {
                lock_state = false;
                for (int i = 0; i < 6; i++){
                    door_password_buffer[i] = '\0';
                }
                count_input = 0;
                ESP_LOGI(TAG, "Door unlocked via MQTT");

            } else {
                ESP_LOGW(TAG, "Received invalid door control command via MQTT");
            }
        }
        // printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
        // printf("LEN = %d DATA=%.*s\r\n", event->data_len, event->data_len, event->data);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));

        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}


static void mqtt_app_start(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = "mqtt://192.168.241.198:1883",
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler2 */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler2, NULL);
    esp_mqtt_client_start(client);
}




static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = CONFIG_ESP_WIFI_SSID,
            .password = CONFIG_ESP_WIFI_PASSWORD,
            .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
            .sae_pwe_h2e = ESP_WIFI_SAE_MODE,
            .sae_h2e_identifier = EXAMPLE_H2E_IDENTIFIER,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                 CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
                 CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}



void app_main(void)
{
    esp_err_t ret;

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Load password from NVS, fallback to default if not found
    ret = load_password_from_nvs(door_password, sizeof(door_password));
    if (ret != ESP_OK) {
        ESP_LOGI(TAG, "Using default password: 123456");
        ret = save_password_to_nvs(door_password, sizeof(door_password));
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save default password to NVS");
            return;
        }
    }


    if (CONFIG_LOG_MAXIMUM_LEVEL > CONFIG_LOG_DEFAULT_LEVEL) {
        esp_log_level_set("wifi", CONFIG_LOG_MAXIMUM_LEVEL);
    }
    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();
    mqtt_app_start();    
    // Initialize keypad
    ESP_ERROR_CHECK(matrix_keypad_init(&keypad));
    pass_input_buffer = xQueueCreate(10, sizeof(uint32_t));
    xTaskCreate(password_check, "password_check", 2048, NULL, 10, NULL);
    while(1) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}
