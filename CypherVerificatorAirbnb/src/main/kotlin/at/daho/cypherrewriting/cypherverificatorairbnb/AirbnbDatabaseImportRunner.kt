package at.daho.cypherrewriting.cypherverificatorairbnb

import org.apache.commons.csv.CSVFormat
import org.apache.commons.csv.CSVRecord
import org.neo4j.driver.Query
import org.neo4j.driver.Session
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.time.LocalDate
import java.util.zip.GZIPInputStream

@Component
@Profile("airbnb-import")
class AirbnbDatabaseImportRunner: ApplicationRunner {

    @Autowired
    lateinit var session: Session

    private val listingsPath = "/data/listings.csv.gz"
    private val reviewsPath = "/data/reviews.csv.gz"

    private val amenitiesRegex = Regex("\"(.*?)\"")

    /* Columns for listings
    id, listing_url, scrape_id, last_scraped, source, name, description, neighborhood_overview, picture_url, host_id,
    host_url, host_name, host_since, host_location, host_about, host_response_time, host_response_rate,
    host_acceptance_rate, host_is_superhost, host_thumbnail_url, host_picture_url, host_neighbourhood,
    host_listings_count, host_total_listings_count, host_verifications, host_has_profile_pic, host_identity_verified,
    neighbourhood, neighbourhood_cleansed, neighbourhood_group_cleansed, latitude, longitude, property_type, room_type,
    accommodates, bathrooms, bathrooms_text, bedrooms, beds, amenities, price, minimum_nights, maximum_nights,
    minimum_minimum_nights, maximum_minimum_nights, minimum_maximum_nights, maximum_maximum_nights,
    minimum_nights_avg_ntm, maximum_nights_avg_ntm, calendar_updated, has_availability, availability_30,
    availability_60, availability_90, availability_365, calendar_last_scraped, number_of_reviews,
    number_of_reviews_ltm, number_of_reviews_l30d, availability_eoy, number_of_reviews_ly, estimated_occupancy_l365d,
    estimated_revenue_l365d, first_review, last_review, review_scores_rating, review_scores_accuracy,
    review_scores_cleanliness, review_scores_checkin, review_scores_communication, review_scores_location,
    review_scores_value, license, instant_bookable, calculated_host_listings_count,
    calculated_host_listings_count_entire_homes, calculated_host_listings_count_private_rooms,
    calculated_host_listings_count_shared_rooms, reviews_per_month
     */

    /* Columns for reviews
    listing_id	id	date	reviewer_id	reviewer_name	comments
    */

    override fun run(args: ApplicationArguments) {

        session.run("MATCH (n) DETACH DELETE n")
        importListings(session)
        importReviews(session)

    }

    private fun importListings(session: Session) {
        var currentCount = 0
        getListings().forEach { listing ->
            currentCount++
            if (currentCount % 1000 == 0) {
                print("\rImporting ${currentCount}/${getListings().size}: ${listing.id}: ${listing.name}")
            }

            val ctx = QueryContext()
            val importQuery = """
                MERGE (l:Listing {id: ${ctx.param( listing.id)}})
                ON CREATE SET l.name = ${ctx.param(listing.name)}
                WITH l
                
                MERGE (h:Host {id: ${ctx.param(listing.host.id)}})
                ON CREATE SET h.name = ${ctx.param(listing.host.name)}
                MERGE (h)-[:HOSTS]->(l)
                WITH l
                
                UNWIND ${ctx.param(listing.amenities)} as amenity
                MERGE (a:Amenity {name: amenity}) 
                WITH a, l
                
                MERGE (l)-[:HAS]->(a)
            """

            session.run(Query(importQuery, ctx.params))
        }
    }

    private fun importReviews(session: Session) {
        var currentCount = 0
        getReviews().forEach { review ->
            currentCount++
            if (currentCount % 1000 == 0) {
                print("\rImporting ${currentCount}/${getReviews().size}: ${review.id}")
            }

            val ctx = QueryContext()
            val importQuery = """
                MERGE (r:Review {id: ${ctx.param(review.id)}})
                ON CREATE SET r.date = ${ctx.param(review.date)},
                              r.comments = ${ctx.param(review.comments)}
                WITH r
                
                MERGE (u:User {id: ${ctx.param(review.reviewer.id)}})
                ON CREATE SET u.name = ${ctx.param(review.reviewer.name)}
                WITH r, u
                
                MERGE (u)-[:WROTE]->(r)
                WITH r
                
                MATCH (l:Listing {id: ${ctx.param(review.listingId)}})
                WITH r, l
                
                MERGE (r)-[:REVIEWS]->(l)
            """

            session.run(Query(importQuery, ctx.params))
        }
    }

    private fun getListings(): List<Listing> {
        val stream = {}::class.java.getResourceAsStream(listingsPath)
        GZIPInputStream(stream).bufferedReader(Charsets.UTF_8).use { fileReader ->
            return CSVFormat.Builder.create(CSVFormat.DEFAULT).setHeader().get().parse(fileReader).records.filter { it["id"] != null }.map { toListing(it) }
        }
    }

    private fun getReviews(): List<Review> {
        val stream = {}::class.java.getResourceAsStream(reviewsPath)
        GZIPInputStream(stream).bufferedReader(Charsets.UTF_8).use { fileReader ->
            return CSVFormat.Builder.create(CSVFormat.DEFAULT).setHeader().get().parse(fileReader).records.filter { it["id"] != null }.map { toReview(it) }
        }
    }

    private fun toListing(record: CSVRecord): Listing {
        return Listing(
            id = record["id"].toLong(),
            name = record["name"] as String,
            amenities = amenitiesToList(record["amenities"]),
            host = toHost(record),
            price = record["price"],
        )
    }

    private fun amenitiesToList(rawAmenities: String): Set<String> {
        return amenitiesRegex.findAll(rawAmenities).mapNotNull { it.groups[1]?.value }.filter { it.isNotBlank() }.toSet()
    }

    private fun toHost(record: CSVRecord): Host {
        return Host(
            id = record["host_id"].toLong(),
            name = record["host_name"],
        )
    }

    private fun toReview(record: CSVRecord): Review {
        val reviewer = Reviewer(
            id = record["reviewer_id"].toLong(),
            name = record["reviewer_name"],
        )

        return Review(
            id = record["id"].toLong(),
            listingId = record["listing_id"].toLong(),
            date = LocalDate.parse(record["date"]),
            reviewer = reviewer,
            comments = record["comments"],
        )
    }
}

data class Listing(
    val id: Long,
    val name: String,
    val amenities: Set<String>,
    val host: Host,
    val price: String,
)

data class Host(
    val id: Long,
    val name: String,
)

data class Review(
    val id: Long,
    val listingId: Long,
    val date: LocalDate,
    val reviewer: Reviewer,
    val comments: String
)

data class Reviewer (
    val id: Long,
    val name: String,
)

class QueryContext {
    val params: MutableMap<String, Any> = mutableMapOf()

    fun namedParam(name: String, value: Any): String {
        if (name in params) {
            throw IllegalArgumentException("$name is already defined.")
        }
        params[name] = value
        return "$$name"
    }

    fun param(value: Any): String {
        var cnt = params.size
        var name: String
        do {
            name = "param$cnt"
            cnt++
        } while (name in params)

        params[name] = value
        return "$$name"
    }

    fun namedParam(name: String): String {
        if (name !in params) {
            throw IllegalArgumentException("$name is not defined.")
        }
        return "$$name"
    }

}
