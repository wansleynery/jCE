import com.sun.jna.Native
import java.nio.ByteBuffer
import java.nio.ByteOrder

// Representa o valor lido do endereço (para facilitar filtros)
data class MemSample (val bytes: ByteArray) {

    // Interpreta o valor como inteiro/ponteiro (little endian)
    fun asU64 (): Long {
        val b = if (bytes.size >= 8)
            bytes.copyOfRange (0, 8)
        else
            bytes.copyOf ()

        val bb = ByteBuffer.wrap (b).order (ByteOrder.LITTLE_ENDIAN)

        return if (Native.POINTER_SIZE == 8)
            bb.long
        else
            (bb.int.toLong () and 0xFFFFFFFFL)
    }

    override fun equals (other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as MemSample
        return bytes.contentEquals (other.bytes)
    }

    override fun hashCode (): Int {
        return bytes.contentHashCode ()
    }
}