import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT.MEMORY_BASIC_INFORMATION
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.ptr.IntByReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.min

object Memory {

    // Lê um bloco de memória (endereço, tamanho) retornando bytes ou null
    fun read (
        handle: WinNT.HANDLE,
        address: Long,
        size: Int
    ): ByteArray? {

        val buffer = Memory (size.toLong ())
        val bytesRead = IntByReference (0)
        val ok = Kernel32.INSTANCE.ReadProcessMemory (
            handle,
            Pointer.createConstant (address),
            buffer,
            size,
            bytesRead
        )

        return if (ok && bytesRead.value > 0) {
            buffer.getByteArray (0, bytesRead.value)
        } else null
    }

    /**
     * Varre regiões commitadas e legíveis do processo e faz scan por possíveis ponteiros.
     * Retorna até `maxPointers` ponteiros (endereços) coletados.
     */
    fun listPointers (
        handle: WinNT.HANDLE,
        maxPointers: Int = -1
    ): List <Long> {

        val kernel      = Kernel32.INSTANCE
        val pointerSize = Native.POINTER_SIZE    // 4 ou 8
        val memInfo     = MEMORY_BASIC_INFORMATION ()
        val results     = mutableListOf <Long> ()

        // Endereço inicial (0) e limite pragmático (para 64-bit usa 0x7FFF...; aqui usamos Long.MAX)
        var address = Pointer.createConstant (0L)

        val maximumResults = if (maxPointers < 1) Int.MAX_VALUE else maxPointers
        while (results.size < maximumResults) {

            // VirtualQueryEx retorna o tamanho preenchido ou 0 em falha
            val memInfoSize = BaseTSD.SIZE_T (memInfo.size ().toLong ())
            val rc = kernel.VirtualQueryEx (handle, address, memInfo, memInfoSize)
            if (rc.toLong () == 0L) break

            val baseAddr   = Pointer.nativeValue (memInfo.baseAddress)
            val regionSize = memInfo.regionSize.toLong () // Tamanho da região

            // Filtrar somente regiões commitadas com permissão de leitura
            val stateCommitted = memInfo.state.toInt () == WinNT.MEM_COMMIT
            val protect = memInfo.protect.toInt ()
            val readable = (
                (protect and Kernel32.PAGE_READWRITE)         != 0 ||
                (protect and Kernel32.PAGE_READONLY)          != 0 ||
                (protect and Kernel32.PAGE_WRITECOPY)         != 0 ||
                (protect and Kernel32.PAGE_EXECUTE_READ)      != 0 ||
                (protect and Kernel32.PAGE_EXECUTE_READWRITE) != 0
            )

            if (stateCommitted && readable) {

                // Ler em blocos menores para não estourar
                var offset = 0L
                val blockMax = 64 * 1024   // 64 KB por bloco

                while (offset < regionSize && results.size < maximumResults) {

                    val toRead = min (blockMax.toLong (), regionSize - offset).toInt ()
                    val addrToRead = baseAddr + offset
                    val data = read (handle, addrToRead, toRead) ?: break

                    // Scanneia o bloco por palavras do tamanho do ponteiro
                    val buf = ByteBuffer.wrap (data).order (ByteOrder.LITTLE_ENDIAN)
                    var i = 0

                    while (i + pointerSize <= toRead && results.size < maximumResults) {

                        val candidate = if (pointerSize == 8) {
                            buf.getLong (i)
                        } else {
                            buf.getInt (i).toLong () and 0xFFFFFFFFL
                        }

                        // Heurística simples: ponteiro não nulo e apontando dentro do espaço do processo
                        if (candidate >= 0x10000L && isReadableAddress (handle, candidate)) { /* evita low-memory null-like */
                            // guarda o ENDEREÇO onde o ponteiro está salvo
                            val slotAddress = addrToRead + i
                            results.add (slotAddress)
                        }

                        i += pointerSize

                    }

                    offset += toRead
                }
            }

            // Próxima região
            val next = baseAddr + regionSize
            if (next <= Pointer.nativeValue (address)) break // evita loop infinito
            address = Pointer.createConstant (next)
        }

        // Remove duplicados e limita
        return results.distinct ().take (maximumResults)
    }

    fun isReadableAddress (
        handle: WinNT.HANDLE,
        address: Long
    ): Boolean {

        val memoryInformation = MEMORY_BASIC_INFORMATION ()
        val rc2 = Kernel32.INSTANCE.VirtualQueryEx (
            handle,
            Pointer.createConstant (address),
            memoryInformation,
            BaseTSD.SIZE_T (memoryInformation.size ().toLong ())
        )
        if (rc2.toLong () == 0L) return false

        val committed = memoryInformation.state.toInt () == WinNT.MEM_COMMIT
        val protected = memoryInformation.protect.toInt ()
        val readable =
            (protected and WinNT.PAGE_READWRITE)         != 0 ||
            (protected and WinNT.PAGE_READONLY)          != 0 ||
            (protected and WinNT.PAGE_WRITECOPY)         != 0 ||
            (protected and WinNT.PAGE_EXECUTE_READ)      != 0 ||
            (protected and WinNT.PAGE_EXECUTE_READWRITE) != 0

        return committed && readable

    }

    fun close (
        handle: WinNT.HANDLE
    ) {
        Kernel32.INSTANCE.CloseHandle (handle)
    }

}