import io.shiftleft.semanticcpg.language._

@main def taintHints(): Unit = {
  println("# Joern Taint Query Hints")
  println("# 1) Thymeleaf template render sink")
  println("cpg.call.code(\".*templateEngine\\.process.*\").l")
  println("# 2) Elasticsearch @Query placeholders (annotation-based)")
  println("cpg.annotation.name(\"Query\").l")
}
