/**
 * joern_sqli_taint.sc — SQL Injection taint flow 분석 (Joern CPG 기반)
 *
 * 사용법 (joern-cli):
 *   joern --script tools/scripts/joern_sqli_taint.sc \
 *         --params "out=state/joern_sqli_taint.json"
 *
 * CPG는 joern-parse로 미리 생성되어 있어야 함:
 *   joern-parse testbed/<project>/<repo>/<module> -o workspace/cpg.bin
 *   joern --import workspace/cpg.bin --script tools/scripts/joern_sqli_taint.sc
 *
 * 출력 (JSON):
 *   [
 *     {
 *       "source_method":  "controllerMethodName",
 *       "source_class":   "ClassName",
 *       "source_file":    "path/to/Controller.java",
 *       "source_line":    42,
 *       "sink_method":    "executeQuery",
 *       "sink_class":     "...",
 *       "sink_file":      "path/to/Repository.java",
 *       "sink_line":      88,
 *       "flow_repr":      "brief taint path"
 *     }
 *   ]
 */

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes._
import java.io.PrintWriter

@main def run(out: String = "state/joern_sqli_taint.json"): Unit = {

  def esc(s: String): String =
    s.replace("\\", "\\\\")
     .replace("\"", "\\\"")
     .replace("\n", "\\n")
     .replace("\r", "")
     .take(200)   // 너무 긴 repr 잘라내기

  // ── Source: HTTP 파라미터 수신 지점 ──────────────────────────────
  // Spring MVC: @RequestParam / @PathVariable / @RequestBody 파라미터를 받는 메서드
  val httpHandlerAnnotations = Set(
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
    "PatchMapping", "RequestMapping",
  )
  val paramAnnotations = Set(
    "RequestParam", "PathVariable", "RequestBody", "ModelAttribute",
  )

  // HTTP handler 메서드 (컨트롤러 레벨 매핑 어노테이션 보유)
  val httpHandlerMethods = cpg.method
    .where(_.annotation.name(httpHandlerAnnotations.mkString("|")))

  // HTTP 파라미터 (메서드 파라미터 중 HTTP 바인딩 어노테이션 보유)
  val httpSources = httpHandlerMethods
    .parameter
    .where(_.annotation.name(paramAnnotations.mkString("|")))

  // ── Sink: SQL 실행 지점 ──────────────────────────────────────────
  // JDBC / JPA / MyBatis 등의 SQL 실행 메서드
  // MyBatis #{} binding은 PreparedStatement이므로 안전 — 단, ${}는 위험
  // Joern에서는 호출 코드 패턴으로 안전한 binding 여부 판단이 어려우므로
  // SQL 실행 메서드 호출 자체를 sink로 식별하고, 이후 source 분석에서 필터링
  val sqlSinkMethodNames = Set(
    // JDBC
    "execute", "executeQuery", "executeUpdate", "executeBatch",
    "prepareStatement", "prepareCall",
    // JPA / Hibernate
    "createQuery", "createNativeQuery", "createNamedQuery",
    "setParameter",
    // Spring JdbcTemplate
    "query", "queryForObject", "queryForList", "queryForMap",
    "update", "batchUpdate",
    // MyBatis / iBatis (동적 SQL 빌드 메서드만)
    "selectList", "selectOne", "selectMap",
    "insert", "delete",
    // Kotlin ktorm / Exposed (일반적)
    "exec", "toSQL",
  )

  val sqlSinks = cpg.call
    .name(sqlSinkMethodNames.mkString("|"))

  // ── Taint flow 계산 ───────────────────────────────────────────────
  // Joern DataFlowPath: HTTP source → SQL sink
  val flows = httpSources.reachableByFlows(sqlSinks).l

  // ── JSON 직렬화 ───────────────────────────────────────────────────
  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true

  flows.foreach { flow =>
    val elements = flow.elements

    // flow의 첫 번째 요소: source (HTTP parameter)
    val sourceNode = elements.headOption
    // flow의 마지막 요소: sink (SQL call)
    val sinkNode   = elements.lastOption

    def nodeFile(n: Option[AstNode]): String =
      n.flatMap(_.file.name.l.headOption).getOrElse("")
    def nodeLine(n: Option[AstNode]): Int =
      n.flatMap(_.lineNumber).getOrElse(0)
    def nodeMethod(n: Option[AstNode]): String =
      n.flatMap {
        case m: Method => Some(m.name)
        case c: Call   => Some(c.name)
        case p: MethodParameterIn => Some(p.method.name)
        case _ => None
      }.getOrElse("")
    def nodeClass(n: Option[AstNode]): String =
      n.flatMap(_.typeDecl.name.l.headOption).getOrElse("")

    // flow 요약: "SourceMethod -> ... -> sinkMethod"
    val repr = elements.take(4).map {
      case c: Call   => s"${c.name}()"
      case m: Method => m.name
      case p: MethodParameterIn => s"${p.name}:${p.method.name}"
      case x         => x.code.take(40)
    }.mkString(" -> ")

    val json =
      s"""{""" +
      s""""source_method":"${esc(nodeMethod(sourceNode))}",""" +
      s""""source_class":"${esc(nodeClass(sourceNode))}",""" +
      s""""source_file":"${esc(nodeFile(sourceNode))}",""" +
      s""""source_line":${nodeLine(sourceNode)},""" +
      s""""sink_method":"${esc(nodeMethod(sinkNode))}",""" +
      s""""sink_class":"${esc(nodeClass(sinkNode))}",""" +
      s""""sink_file":"${esc(nodeFile(sinkNode))}",""" +
      s""""sink_line":${nodeLine(sinkNode)},""" +
      s""""flow_repr":"${esc(repr)}"""" +
      s"""}"""

    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  writer.println()
  writer.println("]")
  writer.close()
  println(s"Joern SQLi taint 분석 완료: ${flows.size}개 flow → $out")
}
