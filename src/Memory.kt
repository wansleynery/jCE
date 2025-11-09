import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Kernel32Util
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.platform.win32.WinNT.MEMORY_BASIC_INFORMATION
import com.sun.jna.ptr.IntByReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.min
import com.sun.jna.Memory as JnaMemory

/**
 * Utilitário de acesso à memória de processos no Windows via JNA.
 * Leitura, escrita, varredura de padrões e heurísticas de refinamento.
 */
object Memory {

    /** Busca um padrão de bytes em todas as regiões legíveis do processo. */
    fun searchMemory (
        handle: WinNT.HANDLE,
        pattern: ByteArray,
        maxResults: Int = Int.MAX_VALUE
    ): List <Long> {

        val results = mutableListOf <Long> ()
        if (pattern.isEmpty ()) return results

        val memInfo = MEMORY_BASIC_INFORMATION ()
        var address = Pointer.createConstant (0L)
        val kernel = Kernel32.INSTANCE
        val patternSize = pattern.size

        while (results.size < maxResults) {
            val rc = kernel.VirtualQueryEx (handle, address, memInfo, BaseTSD.SIZE_T(memInfo.size().toLong()))
            if (rc.toLong() == 0L) break

            val baseAddress = Pointer.nativeValue (memInfo.baseAddress)
            val regionSize  = memInfo.regionSize.toLong ()
            val committed   = memInfo.state.toInt () == WinNT.MEM_COMMIT
            val protected   = memInfo.protect.toInt ()
            val readable    =
                (protected and WinNT.PAGE_READWRITE)         != 0 ||
                (protected and WinNT.PAGE_READONLY)          != 0 ||
                (protected and WinNT.PAGE_WRITECOPY)         != 0 ||
                (protected and WinNT.PAGE_EXECUTE_READ)      != 0 ||
                (protected and WinNT.PAGE_EXECUTE_READWRITE) != 0

            if (committed && readable) {

                var offset = 0L
                val blockMax = 64 * 1024
                var prevTail: ByteArray? = null

                while (offset < regionSize && results.size < maxResults) {

                    val toRead = min (blockMax.toLong (), regionSize - offset).toInt ()
                    val addrToRead = baseAddress + offset
                    val data = read (handle, addrToRead, toRead) ?: break

                    val searchData = if (prevTail != null) prevTail + data else data

                    var index = indexOf (searchData, pattern, 0)
                    while (index >= 0 && results.size < maxResults) {
                        val absolute = (addrToRead - (prevTail?.size ?: 0)) + index
                        results.add (absolute)
                        index = indexOf (searchData, pattern, index + 1)
                    }

                    prevTail = if (patternSize > 1 && searchData.size >= patternSize - 1) {
                        searchData.copyOfRange (searchData.size - (patternSize - 1), searchData.size)
                    } else {
                        searchData
                    }

                    offset += toRead.toLong ()
                }
            }

            val next = baseAddress + regionSize
            if (next <= Pointer.nativeValue (address)) break
            address = Pointer.createConstant (next)
        }

        return results.distinct ().take (maxResults)
    }

    /** Busca ingênua de subarray. */
    private fun indexOf (
        data: ByteArray,
        pattern: ByteArray,
        start: Int = 0
    ): Int {

        if (pattern.isEmpty () || data.isEmpty () || pattern.size > data.size) return -1

        outer@ for (i in start..(data.size - pattern.size)) {
            for (j in pattern.indices) if (data [i + j] != pattern [j]) continue@outer
            return i
        }

        return -1

    }

    /** Lê um bloco arbitrário de memória do processo. */
    fun read (
        handle: WinNT.HANDLE,
        address: Long,
        size: Int
    ): ByteArray? {

        val buffer = JnaMemory (size.toLong ())

        val bytesRead = IntByReference (0)

        val ok = Kernel32.INSTANCE.ReadProcessMemory (
            handle,
            Pointer.createConstant (address),
            buffer,
            size,
            bytesRead
        )

        return (
            if (ok && bytesRead.value > 0)
                buffer.getByteArray (0, bytesRead.value)
            else
                null
        )
    }

    fun filterAddresses (
        handle: WinNT.HANDLE,
        addresses: List <Long>,
        pattern: ByteArray
    ): List <Long> {
        val size = pattern.size
        return addresses.filter { addr ->
            val data = read (handle, addr, size)
            data != null && data.contentEquals (pattern)
        }
    }

    fun writeWithException (
        handle: WinNT.HANDLE,
        address: Long,
        data: ByteArray
    ): WriteResult {

        // Endereço-alvo -> Pointer
        val base = Pointer.createConstant (address)

        // Buffer -> Pointer (JNA Memory) e copia o ByteArray
        val buf = JnaMemory (data.size.toLong ())
        buf.write (0, data, 0, data.size)

        // nSize -> Int | bytesWritten -> IntByReference
        val bytesWritten = IntByReference ()

        val ok = Kernel32.INSTANCE.WriteProcessMemory (
            handle,
            base,
            buf,
            data.size,
            bytesWritten
        )

        if (!ok) {
            val err = getLastError ()
            return WriteResult (false, err.code, err.message)
        }

        // Checagem extra: Windows pode escrever parcialmente (ERROR_PARTIAL_COPY 299)
        if (bytesWritten.value != data.size) {
            return WriteResult (
                false,
                299,
                "Only part of the WriteProcessMemory request was completed (${bytesWritten.value}/${data.size} bytes)."
            )
        }

        return WriteResult (true)

    }

    /**
     * Varre regiões commitadas e legíveis do processo e faz scan por possíveis ponteiros.
     * Retorna até `maxPointers` ponteiros (endereços) coletados.
     */
    fun listPointers(
        handle: WinNT.HANDLE,
        maxPointers: Int = -1
    ): List<Long> {

        val kernel      = Kernel32.INSTANCE
        val pointerSize = Native.POINTER_SIZE    // 4 ou 8
        val memInfo     = MEMORY_BASIC_INFORMATION ()
        val results     = mutableListOf <Long> ()

        // Endereço inicial (0) e limite pragmático (para 64-bit usa 0x7FFF...; aqui usamos Long.MAX)
        var regionStart = Pointer.createConstant(0L)

        val maximumResults = if (maxPointers < 1) Int.MAX_VALUE else maxPointers
        while (results.size < maximumResults) {

            // VirtualQueryEx retorna o tamanho preenchido ou 0 em falha
            val memInfoSize = BaseTSD.SIZE_T(memInfo.size().toLong())
            val rc = kernel.VirtualQueryEx(handle, regionStart, memInfo, memInfoSize)
            if (rc.toLong () == 0L) break

            val baseAddr = Pointer.nativeValue(memInfo.baseAddress)
            val regionSize = memInfo.regionSize.toLong() // Tamanho da região

            // Filtrar somente regiões commitadas com permissão de leitura
            val stateCommitted = memInfo.state.toInt () == WinNT.MEM_COMMIT
            val protect = memInfo.protect.toInt ()
            val readable = (
                    (protect and WinNT.PAGE_READWRITE)         != 0 ||
                            (protect and WinNT.PAGE_READONLY)          != 0 ||
                            (protect and WinNT.PAGE_WRITECOPY)         != 0 ||
                            (protect and WinNT.PAGE_EXECUTE_READ)      != 0 ||
                            (protect and WinNT.PAGE_EXECUTE_READWRITE) != 0
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
            if (next <= Pointer.nativeValue(regionStart)) break // evita loop infinito
            regionStart = Pointer.createConstant(next)
        }

        // Remove duplicados e limita
        return results.distinct().take(maximumResults)
    }

    fun isReadableAddress(
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

    /** Fecha o handle do processo. */
    fun close (handle: WinNT.HANDLE) {
        Kernel32.INSTANCE.CloseHandle (handle)
    }

    data class WriteResult (
        val ok: Boolean,
        val errorCode: Int? = null,
        val errorMessage: String? = null
    )

    data class LastError (
        val code: Int,
        val message: String
    )

    fun getLastError (): LastError {
        val code = Kernel32.INSTANCE.GetLastError ()
        val msg  = try {
            Kernel32Util.formatMessageFromLastErrorCode (code)
        } catch (_: Throwable) {
            "Win32 error $code"
        }
        return LastError (code, msg.trim ())
    }

}
