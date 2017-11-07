package drt.chroma

import com.typesafe.config.ConfigFactory
import spray.http.FormData

trait ChromaFeedType {
  def toString: String
}
case object ChromaLive extends ChromaFeedType {
  override def toString: String = "live"
}
case object ChromaForecast extends ChromaFeedType {
  override def toString: String = "forecast"
}

trait ChromaConfig {
  lazy val config = ConfigFactory.load()
  def feedType: ChromaFeedType

  val chromaTokenRequestCredentials = FormData(Seq(
    "username" -> config.getString("chroma.username"),
    "password" -> config.getString("chroma.password"),
    "grant_type" -> "password"
  ))
  val tokenUrl: String = config.getString("chroma.url.token")
  val url: String = config.getString(s"chroma.url.$feedType")
}
