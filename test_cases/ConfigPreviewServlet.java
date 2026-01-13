import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ConfigPreviewServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // 污点源 (Source): 从 HTTP 请求获取参数
        String fileName = request.getParameter("file");
        String baseDir = "/opt/app/config/";

        if (fileName != null) {
            // 漏洞点：路径穿越 (Path Traversal)
            // 未对 ".." 等字符进行检查
            File file = new File(baseDir + fileName);

            if (file.exists() && file.canRead()) {
                response.setContentType("text/plain");
                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String line;
                    PrintWriter out = response.getWriter();
                    while ((line = reader.readLine()) != null) {
                        out.println(line);
                    }
                }
            } else {
                // 潜在风险：不安全的系统命令执行
                // 模拟一个"尝试修复"或"日志记录"的逻辑，调用了外部命令
                String cmd = "ls -l " + baseDir + fileName;
                Runtime.getRuntime().exec(cmd); // Sink: 远程代码执行 (RCE)
            }
        }
    }
}
