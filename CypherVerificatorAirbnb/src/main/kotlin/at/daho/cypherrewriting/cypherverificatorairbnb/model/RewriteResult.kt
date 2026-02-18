package at.daho.cypherrewriting.cypherverificatorairbnb.model

import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.Detection

data class RewriteResult(
    val originalQuery: String,
    val rewrittenQuery: String,
    val detections: List<Detection>
)
