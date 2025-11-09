import com.sun.jna.Native
import com.sun.jna.platform.win32.WinNT
import java.nio.ByteBuffer
import java.nio.ByteOrder

object Command {

    // Handle do processo alvo (injete via bind() após selecionar o processo)
    var handle: WinNT.HANDLE? = null
        private set

    // Últimos endereços encontrados (será útil para filter/set na evolução)
    var lastAddresses: List <Long> = emptyList ()
        private set

    fun bind (processHandle: WinNT.HANDLE) {
        handle = processHandle
    }

    fun search (
        type: DataParser.DataType,
        value: Any
    ): List <Long> {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        val initialValue = value.toString ().trim ()

        // Monta padrões de bytes conforme o tipo
        val initialPatterns: List <ByteArray> =
            if (type == DataParser.DataType.STRING) {
                listOf (
                    DataParser.toBytes (type, initialValue),
                    DataParser.toBytesUtf16LE (initialValue)
                )
            } else {
                listOf (DataParser.toBytes (type, initialValue))
            }

        // Busca todos os endereços que contenham o padrão
        var candidateAddresses: List <Long> = buildList {
            for (patternBytes in initialPatterns) {
                addAll (Memory.searchMemory (processHandle, patternBytes))
            }
        }.distinct ()

        // Se for string, filtra apenas as com terminador nulo
        if (type == DataParser.DataType.STRING) {

            candidateAddresses = candidateAddresses.filter { address ->

                initialPatterns.any { patternBytes ->

                    val readSize = patternBytes.size + 2

                    val data = Memory.read (processHandle, address, readSize)
                    if (data != null && data.size >= readSize) {

                        val prefixMatches = data
                            .copyOfRange (0, patternBytes.size)
                            .contentEquals (patternBytes)

                        val terminator = data.copyOfRange (patternBytes.size, patternBytes.size + 2)
                        val hasNullTerminator = terminator.all { b -> b.toInt() == 0 }

                        prefixMatches && hasNullTerminator

                    } else {
                        false
                    }
                }
            }
        }

        lastAddresses = candidateAddresses
        return candidateAddresses

    }

    fun filter (
        addressList: List <Long>,
        type: DataParser.DataType,
        value: Any
    ): List <Long> {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        val refineValue = value.toString ().trim ()

        val refinePatterns: List <ByteArray> =
            if (type == DataParser.DataType.STRING) {
                listOf (
                    DataParser.toBytes (type, refineValue),
                    DataParser.toBytesUtf16LE (refineValue)
                )
            } else {
                listOf (DataParser.toBytes (type, refineValue))
            }

        val filteredAddresses: List <Long> =
            if (type == DataParser.DataType.STRING) {

                addressList.filter { address ->

                    refinePatterns.any { patternBytes ->

                        val readSize = patternBytes.size + 2

                        val data = Memory.read (processHandle, address, readSize)
                        if (data != null && data.size >= readSize) {

                            val prefixMatches = data
                                .copyOfRange (0, patternBytes.size)
                                .contentEquals (patternBytes)

                            val terminator = data.copyOfRange (patternBytes.size, patternBytes.size + 2)
                            val hasNullTerminator = terminator.all { b -> b.toInt () == 0 }

                            prefixMatches && hasNullTerminator

                        } else {
                            false
                        }
                    }
                }

            } else {
                // Para tipos numéricos, comparamos o conteúdo exato do padrão
                Memory.filterAddresses (processHandle, addressList, refinePatterns [0])
            }

        lastAddresses = filteredAddresses
        return filteredAddresses

    }

    fun set (
        addressList: List <Long>,
        type: DataParser.DataType,
        value: Any
    ): SetResult {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        val newValueStr = value.toString ().trim ()

        val updated = mutableListOf <Long> ()
        val failed  = mutableListOf <SetFailure> ()

        when (type) {

            DataParser.DataType.STRING -> {

                for (addr in addressList) {

                    val useUtf16 = isLikelyUtf16LE (processHandle, addr)

                    val payload: ByteArray =
                        if (useUtf16) {
                            // UTF-16LE + terminador nulo de 2 bytes
                            DataParser.toBytesUtf16LE (newValueStr) + byteArrayOf (0x00, 0x00)
                        } else {
                            // UTF-8 (ou padrão do DataParser.toBytes) + terminador nulo
                            DataParser.toBytes (type, newValueStr) + byteArrayOf (0x00)
                        }

                    val wr = Memory.writeWithException (processHandle, addr, payload)
                    if (!wr.ok) {
                        failed.add (
                            SetFailure (
                                address = addr,
                                code    = wr.errorCode ?: -1,
                                message = wr.errorMessage ?: "unknown"
                            )
                        )
                        continue
                    }

                    val verify = Memory.read (processHandle, addr, payload.size)
                    if (verify != null && verify.copyOfRange (0, payload.size).contentEquals (payload)) {
                        updated.add (addr)
                    } else {
                        failed.add (
                            SetFailure (
                                address = addr,
                                code    = 0,
                                message = "verification failed"
                            )
                        )
                    }
                }
            }

            else -> {

                // Numéricos: escreve o buffer exato do tipo
                val bytes = DataParser.toBytes (type, newValueStr)

                for (addr in addressList) {

                    val wr = Memory.writeWithException (processHandle, addr, bytes)
                    if (!wr.ok) {
                        failed.add (
                            SetFailure (
                                address = addr,
                                code    = wr.errorCode ?: -1,
                                message = wr.errorMessage ?: "unknown"
                            )
                        )
                        continue
                    }

                    val verify = Memory.read (processHandle, addr, bytes.size)
                    if (verify != null && verify.copyOfRange (0, bytes.size).contentEquals (bytes)) {
                        updated.add (addr)
                    } else {
                        failed.add (
                            SetFailure (
                                address = addr,
                                code    = 0,
                                message = "verification failed"
                            )
                        )
                    }
                }
            }
        }

        // Mantém estado: apenas endereços atualizados com sucesso
        lastAddresses = updated.toList ()

        return SetResult (
            updated = updated,
            failed  = failed
        )
    }

    data class SetFailure (
        val address: Long,
        val code: Int,
        val message: String
    )

    data class SetResult (
        val updated: List <Long>,
        val failed:  List <SetFailure>
    )

    private fun isLikelyUtf16LE (
        processHandle: WinNT.HANDLE,
        address: Long
    ): Boolean {

        // Heurística simples: se muitos bytes de índice ímpar são 0x00, assume UTF-16LE
        val peek = Memory.read (processHandle, address, 16) ?: return false
        if (peek.size < 4) return false

        var zeroOdd = 0
        var count   = 0
        for (i in 1 until peek.size step 2) {
            count++
            if (peek [i].toInt () == 0) zeroOdd++
        }
        return count > 0 && zeroOdd * 2 >= count  // >= 50% dos pares com byte alto == 0
    }

    /**
     * Procura referências (ponteiros) que contenham o endereço alvo.
     * Retorna lista de endereços onde o ponteiro (little-endian) foi encontrado.
     *
     * Nota: metodo silencioso — não faz prints. Atualiza lastAddresses com os resultados.
     */
    fun pointerScan (
        targetAddress: Long,
        maxResults: Int = 500
    ): List<Long> {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        val pattern: ByteArray = when (val ptrSize = Native.POINTER_SIZE) {
            8 -> ByteBuffer
                .allocate (8)
                .order (ByteOrder.LITTLE_ENDIAN)
                .putLong (targetAddress)
                .array ()
            4 -> ByteBuffer
                .allocate (4)
                .order (ByteOrder.LITTLE_ENDIAN)
                .putInt (targetAddress.toInt ())
                .array ()
            else -> throw IllegalStateException ("Unsupported pointer size: $ptrSize")
        }

        val found = Memory.searchMemory (processHandle, pattern, maxResults).distinct ()
        lastAddresses = found
        return found
    }

    /**
     * Para cada endereço em `targets`, busca endereços onde há um ponteiro
     * (little-endian) igual ao target. Retorna mapa target -> [endereços que apontam para ele].
     * Silencioso: não faz prints. Usa Memory.searchMemory internamente.
     */
    fun pointerScanMany (
        targets: List<Long>,
        perTargetLimit: Int = 500
    ): Map <Long, List <Long>> {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        val out = mutableMapOf <Long, List <Long>> ()
        for (t in targets) {
            val found = pointerScan (t, perTargetLimit)
            out [t] = found
        }
        return out
    }

    /**
     * Faz um breadth-first "pointer chain scan" para subir a cadeia de referências.
     *
     * startTargets: endereços iniciais (por exemplo os resultados atuais).
     * maxDepth: profundidade máxima de subida (1..N). 1 = procurar quem aponta para target.
     * perLayerLimit: limite de resultados por busca para evitar explosão.
     *
     * Retorna lista de cadeias. Cada cadeia é List<Long> do root (mais alto) até o target.
     */
    fun pointerChainScan (
        startTargets: List <Long>,
        maxDepth: Int = 4,
        perLayerLimit: Int = 300
    ): List <List <Long>> {

        val processHandle = handle
            ?: error ("Process handle não definido. Chame Command.bind (handle) após selecionar o processo.")

        if (startTargets.isEmpty ()) return emptyList ()

        // child -> parents (quem aponta para child)
        val parentsMap = mutableMapOf <Long, MutableList <Long>> ()

        // visited evita re-scan do mesmo endereço
        val visited = mutableSetOf <Long> ()

        // camada atual começa nos targets
        var currentLayer = startTargets.toSet ()

        visited.addAll (currentLayer)

        for (depth in 1..maxDepth) {

            val nextLayer = mutableSetOf <Long> ()

            for (child in currentLayer) {

                // procura referências que contenham o ponteiro para `child`
                val parents = pointerScan (child, perLayerLimit)

                for (p in parents) {
                    if (!parentsMap.containsKey (child)) parentsMap [child] = mutableListOf ()
                    if (!parentsMap [child]!!.contains (p)) parentsMap[child]!!.add (p)
                    if (!visited.contains (p)) {
                        nextLayer.add (p)
                        visited.add (p)
                    }
                }
            }

            if (nextLayer.isEmpty ()) break
            currentLayer = nextLayer
        }

        // Reconstroi cadeias de root -> ... -> target para cada target
        val chains = mutableListOf <List <Long>> ()

        fun buildChainsRec (addr: Long): List <List <Long>> {
            val ps = parentsMap [addr]
            if (ps == null || ps.isEmpty ()) {
                // sem pais => cadeia única contendo só o nó atual (será concatenada depois)
                return listOf (listOf (addr))
            }
            val out = mutableListOf <List <Long>> ()
            for (p in ps) {
                val upstream = buildChainsRec (p)
                for (u in upstream) {
                    // concatena: upstream chain + current addr
                    out.add (u + addr)
                }
            }
            return out
        }

        for (t in startTargets) {
            val built = buildChainsRec (t)
            // built já é [root...child...t], garantimos unicidade
            chains.addAll (built)
        }

        // remove duplicados exatos e limite tamanhos (safety)
        val unique = chains.map { it }.distinct ().take (1000)
        return unique

    }


}