import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/seed_joern.json"): Unit = {
  def esc(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  }

  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  def emit(label: String, c: Call): Unit = {
    val file = c.file.name.l.headOption.getOrElse("")
    val line = c.lineNumber.getOrElse(0)
    val code = c.code
    val json = s"""{\"label\":\"${esc(label)}\",\"file\":\"${esc(file)}\",\"line\":$line,\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  // Template processing (potential SSTI/XSS sink)
  cpg.call.code(".*templateEngine\\.process.*").l.foreach(c => emit("template_process", c))

  // File handling sinks
  cpg.call.name("FileInputStream|FileOutputStream|Files\\..*|File\\..*").l.foreach(c => emit("file_io", c))

  // Data protection / crypto usage hints
  cpg.call.name("Cipher|getInstance|MessageDigest|Mac|SecretKeySpec|Jwt|JWT").l.foreach(c => emit("crypto_usage", c))

  writer.println()
  writer.println("]")
  writer.close()
}
