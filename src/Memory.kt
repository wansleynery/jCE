import com.sun.jna.Memory as JnaMemory
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

        val buffer = JnaMemory(size.toLong())
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

    /**
     * Busca um padrão arbitrário de bytes (como inteiros, floats, strings, etc.) em todas
     * as regiões de memória commitadas e legíveis de um processo. Esta função percorre
     * as regiões de memória de forma semelhante ao metodo listPointers, lendo blocos
     * de dados e procurando pela sequência de bytes especificada. Ao encontrar uma
     * ocorrência, adiciona o endereço absoluto do início da ocorrência à lista de
     * resultados. Para evitar estourar a memória, o usuário pode limitar o número
     * máximo de resultados através do parâmetro `maxResults`.
     *
     * Observação: para melhorar a performance em grandes volumes de memória, a
     * pesquisa é feita em blocos de 64 KiB e são mantidos alguns bytes do final do
     * bloco anterior (tail) para detectar padrões que se cruzem entre dois blocos.
     *
     * @param handle Handle do processo a ser varrido.
     * @param pattern Array de bytes que representa o valor a ser buscado.
     * @param maxResults Número máximo de endereços a retornar (padrão: ilimitado).
     * @return Lista de endereços absolutos onde o padrão foi encontrado.
     */
    fun searchMemory(
        handle: WinNT.HANDLE,
        pattern: ByteArray,
        maxResults: Int = Int.MAX_VALUE
    ): List<Long> {

        val results = mutableListOf<Long>()
        if (pattern.isEmpty()) return results

        val memInfo = MEMORY_BASIC_INFORMATION()
        var address = Pointer.createConstant(0L)
        val kernel = Kernel32.INSTANCE

        val patternSize = pattern.size

        while (results.size < maxResults) {
            // Descreve a região de memória atual
            val rc = kernel.VirtualQueryEx(
                handle,
                address,
                memInfo,
                BaseTSD.SIZE_T(memInfo.size().toLong())
            )
            if (rc.toLong() == 0L) break

            val baseAddr = Pointer.nativeValue(memInfo.baseAddress)
            val regionSize = memInfo.regionSize.toLong()

            // filtra regiões commitadas e com permissão de leitura
            val stateCommitted = memInfo.state.toInt() == WinNT.MEM_COMMIT
            val protect = memInfo.protect.toInt()
            val readable =
                (protect and WinNT.PAGE_READWRITE)         != 0 ||
                (protect and WinNT.PAGE_READONLY)          != 0 ||
                (protect and WinNT.PAGE_WRITECOPY)         != 0 ||
                (protect and WinNT.PAGE_EXECUTE_READ)      != 0 ||
                (protect and WinNT.PAGE_EXECUTE_READWRITE) != 0

            if (stateCommitted && readable) {
                var offset = 0L
                val blockMax = 64 * 1024 // 64 KiB por bloco
                var prevTail: ByteArray? = null

                while (offset < regionSize && results.size < maxResults) {
                    val toRead = min(blockMax.toLong(), regionSize - offset).toInt()
                    val addrToRead = baseAddr + offset
                    val data = read(handle, addrToRead, toRead) ?: break

                    // combina a cauda anterior com os dados atuais para detectar padrões que atravessam blocos
                    val searchData = if (prevTail != null) {
                        prevTail + data
                    } else {
                        data
                    }

                    var idx = indexOf(searchData, pattern, 0)
                    while (idx >= 0 && results.size < maxResults) {
                        // calcula endereço absoluto, levando em conta o tamanho da cauda anterior
                        val absoluteAddr = (addrToRead - (prevTail?.size ?: 0)) + idx
                        results.add(absoluteAddr)
                        idx = indexOf(searchData, pattern, idx + 1)
                    }

                    // prepara a cauda para a próxima iteração: últimos (patternSize - 1) bytes
                    prevTail = if (patternSize > 1 && searchData.size >= patternSize - 1) {
                        searchData.copyOfRange(
                            searchData.size - (patternSize - 1),
                            searchData.size
                        )
                    } else {
                        searchData
                    }

                    offset += toRead.toLong()
                }
            }

            // avança para a próxima região
            val next = baseAddr + regionSize
            if (next <= Pointer.nativeValue(address)) break // evita loop infinito
            address = Pointer.createConstant(next)
        }

        // remove duplicados e limita a quantidade de resultados
        return results.distinct().take(maxResults)
    }

    /**
     * Filtra uma lista de endereços verificando se o conteúdo da memória nesses endereços
     * é exatamente igual ao padrão fornecido. Os endereços para os quais a leitura falha
     * ou cujo conteúdo não coincide são descartados.
     *
     * @param handle Handle do processo a ler.
     * @param addresses Lista de endereços candidatos.
     * @param pattern Padrão de bytes a comparar.
     * @return Lista de endereços cujo conteúdo corresponde ao padrão.
     */
    fun filterAddresses(
        handle: WinNT.HANDLE,
        addresses: List<Long>,
        pattern: ByteArray
    ): List<Long> {
        val size = pattern.size
        return addresses.filter { addr ->
            val data = read(handle, addr, size)
            data != null && data.contentEquals(pattern)
        }
    }

    /**
     * Retorna o índice da primeira ocorrência de um padrão dentro de um array de bytes.
     * Caso o padrão não seja encontrado, retorna -1. A pesquisa começa a partir do
     * índice indicado por `start`. Esta função auxilia a implementação de `searchMemory`.
     *
     * @param data Array de bytes onde será feita a busca.
     * @param pattern Padrão de bytes a ser encontrado.
     * @param start Posição inicial na qual começar a procurar.
     * @return Índice da primeira ocorrência ou -1 se não encontrado.
     */
    private fun indexOf(
        data: ByteArray,
        pattern: ByteArray,
        start: Int = 0
    ): Int {
        if (pattern.isEmpty() || data.isEmpty() || pattern.size > data.size) return -1
        outer@ for (i in start..(data.size - pattern.size)) {
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) continue@outer
            }
            return i
        }
        return -1
    }

}