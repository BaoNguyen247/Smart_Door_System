idf_component_register(SRCS "station_example_main.c"
                    PRIV_REQUIRES esp_wifi nvs_flash esp_common esp_driver_gpio esp-idf-rc522 esp_driver_i2c nvs_flash esp_driver_i2s esp_driver_spi esp_driver_uart esp_event esp_timer freertos json mqtt
                    INCLUDE_DIRS ".")
