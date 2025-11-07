import com.sun.jna.Native

object UI {
    fun printLine (
        left: String,
        value: String,
        width: Int = 30
    ): String {
        val right = "0x" + value.uppercase ().padStart (Native.POINTER_SIZE * 2, '0')
        val dots = ".".repeat ((width - left.length - right.length).coerceAtLeast (1))
        return "$left $dots $right"
    }
}