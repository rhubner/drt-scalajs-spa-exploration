package services

import java.util.{UUID, Date}

import spatutorial.shared._

import scala.util.Random

class ApiService extends Api {
  var todos = Seq(
    TodoItem("41424344-4546-4748-494a-4b4c4d4e4f50", 0x61626364, "Wear shirt that says “Life”. Hand out lemons on street corner.", TodoLow, completed = false),
    TodoItem("2", 0x61626364, "Make vanilla pudding. Put in mayo jar. Eat in public.", TodoNormal, completed = false),
    TodoItem("3", 0x61626364, "Walk away slowly from an explosion without looking back.", TodoHigh, completed = false),
    TodoItem("4", 0x61626364, "Sneeze in front of the pope. Get blessed.", TodoNormal, completed = true)
  )

  override def welcomeMsg(name: String): String = {
    println("welcomeMsg")
    s"Welcome to SPA, $name! Time is now ${new Date}"
  }

  override def getAllTodos(): Seq[TodoItem] = {
    // provide some fake Todos
    Thread.sleep(3000)
    println(s"Sending ${todos.size} Todo items")
    todos
  }

  // update a Todo
  override def updateTodo(item: TodoItem): Seq[TodoItem] = {
    // TODO, update database etc :)
    if (todos.exists(_.id == item.id)) {
      todos = todos.collect {
        case i if i.id == item.id => item
        case i => i
      }
      println(s"Todo item was updated: $item")
    } else {
      // add a new item
      val newItem = item.copy(id = UUID.randomUUID().toString)
      todos :+= newItem
      println(s"Todo item was added: $newItem")
    }
    Thread.sleep(300)
    todos
  }

  // delete a Todo
  override def deleteTodo(itemId: String): Seq[TodoItem] = {
    println(s"Deleting item with id = $itemId")
    Thread.sleep(300)
    todos = todos.filterNot(_.id == itemId)
    todos
  }

  val numberOf15Mins = (24 * 4 * 15)
  private val maxLoadPerSlot: Int = 20
  private val workload: Seq[Double] = Iterator.continually(Random.nextDouble() * maxLoadPerSlot).take(numberOf15Mins).toSeq

  def getWorkloads(): Seq[Double] = {
    workload
  }

  override def crunch(workloads: Seq[Double]): CrunchResult = {
    println(s"Crunch requested for ${workloads}")
    val repeat = List.fill[Int](workloads.length)_
    TryRenjin.crunch(workloads, repeat(10), repeat(15))
  }

  override def processWork(workloads: Seq[Double], desks: Seq[Int]): SimulationResult = {
    println(s"processWork")
    TryRenjin.processWork(workloads, desks)
  }
}
