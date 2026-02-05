import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

// Joern taint heuristics for pcona-ad (NoSQL injection, SSTI)
@main def run(out: String = "state/seed_joern_taint.json"): Unit = {
  def esc(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  }

  def emit(writer: PrintWriter, rule: String, src: AstNode, sink: AstNode): Unit = {
    val srcFile = src.file.name.l.headOption.getOrElse("")
    val srcLine = src.lineNumber.getOrElse(0)
    val sinkFile = sink.file.name.l.headOption.getOrElse("")
    val sinkLine = sink.lineNumber.getOrElse(0)
    val json = s"""{\"rule\":\"${esc(rule)}\",\"source\":{\"file\":\"${esc(srcFile)}\",\"line\":$srcLine,\"code\":\"${esc(src.code)}\"},\"sink\":{\"file\":\"${esc(sinkFile)}\",\"line\":$sinkLine,\"code\":\"${esc(sink.code)}\"},\"path_length\":0}"""
    writer.println(json)
  }

  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  def writeEntry(rule: String, src: AstNode, sink: AstNode): Unit = {
    if (!first) writer.println(",")
    emit(writer, rule, src, sink)
    first = false
  }

  // NoSQL injection heuristic: keyword parameter -> findAllByKeyword call in same method
  val nosqlSinks = cpg.call.name("findAllByKeyword").l
  nosqlSinks.foreach { sink =>
    val m = sink.method
    val srcOpt = m.parameter.name("keyword").headOption
      .orElse(m.ast.isIdentifier.name("keyword").headOption)
    srcOpt.foreach { src =>
      writeEntry("nosql_injection_heuristic", src, sink)
    }
  }

  // SSTI heuristic: adPanel.html / html variable -> doTemplate/process in same method
  val sstiSinks = cpg.call.name("doTemplate|process").l
  sstiSinks.foreach { sink =>
    val m = sink.method
    val srcOpt = m.ast.isIdentifier.name("html").headOption
      .orElse(m.ast.isCall.code(".*adPanel\\.html.*").headOption)
    srcOpt.foreach { src =>
      writeEntry("ssti_heuristic", src, sink)
    }
  }

  writer.println()
  writer.println("]")
  writer.close()
}
