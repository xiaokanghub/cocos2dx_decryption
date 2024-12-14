#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

void processDirectory(const char *directory, const char *key);

int deEncryptPng(
        const unsigned char *inputData,  // 本地读取的加密PNG数据（不含PNG头和IEND）
        size_t inputLen,                 // inputData长度
        const char *key,                 // 异或密钥字符串
        unsigned char *outputData        // 输出的完整解密PNG数据
)
{
    // 计算密钥长度
    size_t keyLen = strlen(key);

    // 总输出长度 = 输入长度 + 8字节PNG头 + 12字节IEND = inputLen + 20
    size_t outputLen = inputLen + 20;

    // 写入PNG标准头部：89 50 4E 47 0D 0A 1A 0A
    // (标准PNG文件头)
    outputData[0] = 0x89;
    outputData[1] = 0x50;
    outputData[2] = 0x4E;
    outputData[3] = 0x47;
    outputData[4] = 0x0D;
    outputData[5] = 0x0A;
    outputData[6] = 0x1A;
    outputData[7] = 0x0A;

    // 将输入数据拷贝到outputData的第8字节开始的位置
    memcpy(outputData + 8, inputData, inputLen);

    // 写入IEND块到尾部
    // IEND块共12字节：00 00 00 00 49 45 4E 44 AE 42 60 82
    size_t endPos = outputLen - 12;
    outputData[endPos + 0]  = 0x00;
    outputData[endPos + 1]  = 0x00;
    outputData[endPos + 2]  = 0x00;
    outputData[endPos + 3]  = 0x00;
    outputData[endPos + 4]  = 0x49; // 'I'
    outputData[endPos + 5]  = 0x45; // 'E'
    outputData[endPos + 6]  = 0x4E; // 'N'
    outputData[endPos + 7]  = 0x44; // 'D'
    outputData[endPos + 8]  = 0xAE;
    outputData[endPos + 9]  = 0x42;
    outputData[endPos + 10] = 0x60;
    outputData[endPos + 11] = 0x82;

    // 异或处理区域：从offset=8一直到(outputLen - 13)字节位置
    // 这对应原代码中v8 = a4 - 13的逻辑
    if (outputLen > 20) {
        size_t start = 8;
        size_t stop = outputLen - 13; // 包含此位置
        size_t idx = 0;
        for (size_t i = start; i <= stop; i++) {
            if (idx >= keyLen) idx = 0;
            outputData[i] ^= (unsigned char)key[idx++];
        }
    }

    // 返回密钥长度（根据原函数返回值逻辑）
    return (int)keyLen;
}

void processDirectory(const char *directory, const char *key) {
    DIR *dp = opendir(directory);
    if (!dp) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char inputPath[1024];
    char outputPath[1024];
    struct stat st;

    while ((entry = readdir(dp)) != NULL) {
        // 跳过.和..目录
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(inputPath, sizeof(inputPath), "%s/%s", directory, entry->d_name);

        // 获取文件状态以判断是否目录
        if (stat(inputPath, &st) == -1) {
            perror("stat");
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // 是目录，递归进入处理
            processDirectory(inputPath, key);
        } else {
            // 是文件，检查扩展名
            const char *ext = strrchr(entry->d_name, '.');
            if (!ext || strcmp(ext, ".png") != 0) {
                continue;
            }

            // 打开输入文件
            FILE *fp = fopen(inputPath, "rb");
            if (!fp) {
                perror("fopen input");
                continue;
            }

            // 获取文件大小
            fseek(fp, 0, SEEK_END);
            long fileSize = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (fileSize <= 7) {
                fprintf(stderr, "File %s too small or invalid.\n", inputPath);
                fclose(fp);
                continue;
            }

            // 读取文件数据
            unsigned char *fileData = (unsigned char *)malloc(fileSize);
            if (!fileData) {
                fprintf(stderr, "Memory allocation failed for file %s.\n", inputPath);
                fclose(fp);
                continue;
            }

            size_t bytesRead = fread(fileData, 1, fileSize, fp);
            fclose(fp);
            if (bytesRead != (size_t)fileSize) {
                fprintf(stderr, "Failed to read entire file %s.\n", inputPath);
                free(fileData);
                continue;
            }

            // 加密数据从第7字节之后开始
            const unsigned char *encryptedData = fileData + 7;
            size_t encryptedLen = fileSize - 7;

            // 解密后数据长度
            size_t outputLen = encryptedLen + 20;
            unsigned char *outputData = (unsigned char *)malloc(outputLen);
            if (!outputData) {
                fprintf(stderr, "Memory allocation for output failed for file %s.\n", inputPath);
                free(fileData);
                continue;
            }

            int keyLen = deEncryptPng(encryptedData, encryptedLen, key, outputData);

            // 构建输出文件名：原文件名_dec.png
            char baseName[1024];
            strncpy(baseName, entry->d_name, sizeof(baseName));
            baseName[sizeof(baseName)-1] = '\0';

            char *dotPos = strrchr(baseName, '.');
            if (dotPos) {
                *dotPos = '\0'; // 移除.png后缀
            }

            snprintf(outputPath, sizeof(outputPath), "%s/%s_dec.png", directory, baseName);

            // 写出解密后的文件
            FILE *outFile = fopen(outputPath, "wb");
            if (!outFile) {
                perror("fopen output");
                free(fileData);
                free(outputData);
                continue;
            }

            fwrite(outputData, 1, outputLen, outFile);
            fclose(outFile);

            printf("Decrypted file: %s -> %s\n", inputPath, outputPath);

            free(fileData);
            free(outputData);
        }
    }

    closedir(dp);
}

int main(void) {
    const char *key = "1f8fd1612362fdd6f753f2ee55107d2b"; // 解密密钥
    const char *directory = "C:\\Users\\12649\\Desktop\\native";  // 要遍历的目录路径

    // 开始递归遍历目录并解密
    processDirectory(directory, key);
    return 0;

}
