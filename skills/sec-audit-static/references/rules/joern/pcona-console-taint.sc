import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/seed_joern_console.json"): Unit = {
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  def emit(rule: String, src: AstNode, sink: AstNode, heuristic: Boolean = true): Unit = {
    val srcFile = src.file.name.l.headOption.getOrElse("")
    val srcLine = src.lineNumber.getOrElse(0)
    val sinkFile = sink.file.name.l.headOption.getOrElse("")
    val sinkLine = sink.lineNumber.getOrElse(0)
    val json = s"""{\"rule\":\"${esc(rule)}\",\"source\":{\"file\":\"${esc(srcFile)}\",\"line\":$srcLine,\"code\":\"${esc(src.code)}\"},\"sink\":{\"file\":\"${esc(sinkFile)}\",\"line\":$sinkLine,\"code\":\"${esc(sink.code)}\"},\"path_length\":0,\"heuristic\":${heuristic}}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  // Utils.toSql(...) -> query execution/concat heuristic
  cpg.call.name("toSql").where(_.code(".*Utils\\.toSql.*")).l.foreach { c =>
    val arg = c.argument(1)
    emit("tosql_concat", arg, c)
  }

  // String.format on SQL constants
  cpg.call.name("format").where(_.code(".*SQL.*\\.format.*")).l.foreach { c =>
    val arg = c.argument(1)
    emit("sql_string_format", arg, c)
  }

  // Thymeleaf templateEngine.process
  cpg.call.code(".*templateEngine\\.process.*").l.foreach { c =>
    val arg = c.argument(1)
    emit("template_process", arg, c)
  }

  writer.println()
  writer.println("]")
  writer.close()
}
