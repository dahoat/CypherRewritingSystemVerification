package at.daho.cypherrewriting.cypherverificatorairbnb.model

import at.daho.cypherrewriting.verification.FuzzMetrics
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.Detection
import org.neo4j.driver.Record
import org.neo4j.driver.Result
import org.neo4j.driver.Session
import org.neo4j.driver.types.Node

data class FuzzRunContext(
    val session: Session,
    val originalQuery: String,
    val originalNodes: Set<Node>,
    val originalResult: Result,
    val originalTuples: List<Record>,
    val rewrittenQuery: String,
    val rewrittenNodes: Set<Node>,
    val rewrittenResult: Result,
    val rewrittenTuples: List<Record>,
    val detections: List<Detection>,
    val metrics: FuzzMetrics,
    var errors: MutableList<String> = mutableListOf()
) {
    fun registerError(error: String) {
        errors.add(error)
    }
}
