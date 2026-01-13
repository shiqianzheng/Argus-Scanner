package main

import (
	"database/sql"
	"fmt"
	"net/http"
    "os"
)

// SecureHandler 展示安全的代码模式 - True Negative
func SecureHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	// 1. 安全的 SQL 查询 (参数化)
	query := "SELECT email FROM users WHERE username = $1"
	row := db.QueryRow(query, username) // 使用占位符 $1

	var email string
	err := row.Scan(&email)
	if err != nil {
		http.Error(w, "User not found", 404)
        // 2. 正常错误处理，不应误报
        fmt.Fprintf(os.Stderr, "Database error: %v\n", err)
		return
	}

	w.Write([]byte(email))
}

// LegacyBuffer C 语言缓冲区溢出示例 - True Positive
/*
#include <string.h>
#include <stdio.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // 危险函数 strcpy，没有检查长度
    strcpy(buffer, input); 
}
*/
