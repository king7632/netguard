#include "netguard.h"

int main(int argc, char *argv[])
{
    log_level_t level = LOG_INFO;

    if (argc == 2) {
        if (strcmp(argv[1], "debug") == 0)
            level = LOG_DEBUG;
        else if (strcmp(argv[1], "info") == 0)
            level = LOG_INFO;
        else if (strcmp(argv[1], "alert") == 0)
            level = LOG_ALERT;
    }

    logger_init(level);
    flow_table_init();
    //使用回环端口，避免违规抓包
    start_capture("lo");  
    return 0;
}
