package at.daho.cypherrewriting.fuzzingexperiments

import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import org.springframework.beans.factory.DisposableBean
import org.springframework.beans.factory.annotation.Autowired
import java.io.BufferedWriter
import java.io.FileWriter
import java.io.Writer
import java.nio.file.Path
import java.nio.file.Paths
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import kotlin.io.path.div
import kotlin.io.path.exists

abstract class FuzzRunnerBase: DisposableBean {
    protected var nonExecutableQueryCount: Int = 0
    protected var unequalQueriesCount: Int = 0
    protected var acceptableErrorCount: Int = 0
    protected var queryCount: Int = 0

    private val reportDir: Path
    init {
        val timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmm"))
        reportDir = Paths.get("reports", timestamp)
        if(!reportDir.exists()) {
            reportDir.createDirectories()
        }
    }

    protected val acceptableErrorWriters = mutableMapOf<String, Writer>()
    protected val unequalQueryWriter = getErrorWriter("unparsed_query_unequal.txt")
    protected val nonExecutableQueryWriter = getErrorWriter("non_executable_queries.txt")

    protected val acceptableErrorCodes = setOf("42N38", "22N27")

    @Autowired
    protected lateinit var cypherParser: CypherRewritingParser

    @Autowired
    protected lateinit var astRenderer: CypherRewritingUnparser

    protected fun getAcceptableErrorFile(errorCode: String): Writer {
        return acceptableErrorWriters.computeIfAbsent(errorCode) { getErrorWriter("acceptable-errors_$errorCode.txt") }
    }

    protected fun getErrorWriter(name: String): Writer {
        val path = reportDir / Paths.get(name)
        if(!path.exists()) {
            path.createFile()
        }
        return BufferedWriter(FileWriter(path.toFile()))
    }

    protected fun reportStats() {
        print("\rProcessing query #${queryCount} | Acceptable errors: $acceptableErrorCount, Unequal queries: $unequalQueriesCount, Non-executable queries: $nonExecutableQueryCount")
    }

    protected fun reportAcceptableError(query: String, errorCode: String) {
        acceptableErrorCount++
        getAcceptableErrorFile(errorCode).appendLine(query)
    }

    protected fun reportQueryNotEqual(query: String, unparsedQuery: String) {
        unequalQueriesCount++
        unequalQueryWriter.appendLine("$query =/= $unparsedQuery")
    }

    protected fun reportQueryNotExecutable(query: String, unparsedQuery: String, e: Exception) {
        nonExecutableQueryCount++
        nonExecutableQueryWriter.appendLine("${e.message}: #originalQuery: $query #unparsedQuery: $unparsedQuery")
    }


    override fun destroy() {
        unequalQueryWriter.close()
        nonExecutableQueryWriter.close()
        acceptableErrorWriters.values.forEach{ it.close()}
    }
}
