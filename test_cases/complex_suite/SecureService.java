package com.example.service;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SecureService {

    // 1. 安全的 SQL 查询 (PreparedStatement) - 这是一个 True Negative 用例
    public void getUserById(Connection conn, String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = ?"; // 使用占位符
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        }
    }

    // 2. 安全的文件读取 (白名单验证) - 这是一个 True Negative 用例
    public void readFileSafely(String filename) throws IOException {
        // 严格的文件名验证 (只允许字母数字)
        if (!filename.matches("^[a-zA-Z0-9]+\\.txt$")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        File baseDir = new File("/data/safe_storage/");
        File targetFile = new File(baseDir, filename);

        // 防止路径穿越的规范化检查
        if (!targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new SecurityException("Path traversal attempt detected!");
        }

        if (targetFile.exists() && targetFile.canRead()) {
            // 读取文件...
        }
    }

    // 3. 可能被误报的逻辑
    public void logInfo(String message) {
        // 这里的 if 包含长字符串，之前会导致误报
        if (message.equals("USER_LOGIN_SUCCESS_WITH_VERY_LONG_TOKEN_AND_SESSION_ID_EXAMPLE")) {
            System.out.println("Login success");
        }

        if (message != null) {
            System.out.println(message);
        }
    }
}
