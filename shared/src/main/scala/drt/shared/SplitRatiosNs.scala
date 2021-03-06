package drt.shared

object SplitRatiosNs {
  case class SplitRatios(splits: List[SplitRatio]=Nil, origin: String)

  object SplitSources {
    val AdvPaxInfo = "advPaxInfo"
    val ApiSplitsWithHistoricalEGateAndFTPercentages_Old = "ApiSplitsWithHistoricalEGatePercentage"
    val ApiSplitsWithHistoricalEGateAndFTPercentages = "ApiSplitsWithHistoricalEGateAndFTPercentages"
    val PredictedSplitsWithHistoricalEGateAndFTPercentages = "PredictedSplitsWithHistoricalEGateAndFTPercentages"
    val Historical = "Historical"
    val TerminalAverage = "TerminalAverage"
  }

  object SplitRatios {
    def apply(origin: String, ratios: SplitRatio*): SplitRatios = SplitRatios(ratios.toList, origin)
    def apply(origin: String, ratios: List[SplitRatio]): SplitRatios = SplitRatios(ratios, origin)
  }
  case class SplitRatio(paxType: PaxTypeAndQueue, ratio: Double)
}
