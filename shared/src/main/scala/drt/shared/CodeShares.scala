package drt.shared

object CodeShares {
  def uniqueArrivalsWithCodeShares[GenFlight](apiFlightFromGenFlight: (GenFlight) => Arrival)
                                             (flights: Seq[GenFlight]): List[(GenFlight, Set[Arrival])] = {
    val grouped = flights.groupBy(f =>
      (apiFlightFromGenFlight(f).SchDT, apiFlightFromGenFlight(f).Terminal, apiFlightFromGenFlight(f).Origin)
    )
    grouped.values.map(flights => {
      val mainFlight: GenFlight = flights.sortBy(f => apiFlightFromGenFlight(f).ActPax).reverse.head
      val shares: Set[Arrival] = flights
        .filter(_ != mainFlight)
        .toSet
        .map(apiFlightFromGenFlight)

      (mainFlight, shares)
    }).toList
  }
}
