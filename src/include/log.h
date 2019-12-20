//
// Created by JiYang on 2019-12-14.
//

#ifndef NETUTILITY_LOG_H
#define NETUTILITY_LOG_H

#if __ANDROID__

#include <android/log.h>

#define LOG_D(TAG, ...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#else

#include <iostream>

#define LOG_D(TAG, ...) log_d(TAG, __VA_ARGS__)

void log_d(const char* tag, const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    std::cout << buffer << std::endl;
}

#endif // __ANDROID__
#endif //NETUTILITY_LOG_H
