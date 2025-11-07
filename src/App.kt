import com.sun.jna.Native
import com.sun.jna.platform.win32.WinNT
import main.Properties
import oshi.software.os.OSProcess

/**
 * Classe principal da aplicação. Responsável por interagir com o usuário via CLI,
 * permitindo a seleção de um processo, a definição do tipo de dado e do valor a
 * pesquisar na memória desse processo e o refinamento sucessivo com novos valores.
 */
class App {
    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            // Idioma das mensagens padrão (pode ser estendido no futuro)
            val language = "ptBR"
            // Número máximo de endereços a serem mostrados ao usuário em cada etapa
            val maxDisplayCount = 50

            // === Processo alvo: pergunta, lista, escolhe ===
            val process: OSProcess = Process.selectProcess(language)
            val processID = process.processID
            val processHandle = Process.open(processID)
                ?: error(
                    Properties.get(
                        "$language.error.processCannotBeOpened",
                        mapOf("pid" to processID.toString())
                    )
                )

            try {
                // Solicita ao usuário o tipo de dado a ser procurado
                print("Tipo de dado (int, float, double, string): ")
                val typeInputStr = readlnOrNull()?.trim() ?: ""
                val valueType = try {
                    DataParser.parseType(typeInputStr)
                } catch (e: Exception) {
                    println("Tipo de dado inválido: ${e.message}")
                    return
                }

                // Solicita o valor inicial para a busca
                print("Valor a procurar: ")
                val initialValue = readlnOrNull()?.trim() ?: ""
                if (initialValue.isEmpty()) {
                    println("Valor não pode ser vazio.")
                    return
                }
                // Constrói os padrões de bytes a serem buscados. Para strings, considera tanto UTF-8 quanto UTF-16LE.
                val initialPatterns: List<ByteArray> = if (valueType == DataParser.DataType.STRING) {
                    listOf(
                        DataParser.toBytes(valueType, initialValue),
                        DataParser.toBytesUtf16LE(initialValue)
                    )
                } else {
                    listOf(DataParser.toBytes(valueType, initialValue))
                }

                println("Procurando por valores... isso pode levar alguns segundos.")
                // Realiza a primeira varredura na memória do processo para cada padrão e concatena os resultados
                var candidateAddresses: List<Long> = buildList {
                    for (patternBytes in initialPatterns) {
                        addAll(Memory.searchMemory(processHandle, patternBytes))
                    }
                }.distinct()

                // Filtra resultados para garantir que, no caso de strings, o valor esteja
                // terminado por bytes nulos (\u0000). Isso evita que padrões que são substrings
                // de uma string maior apareçam como candidatos. A verificação lê os dois
                // bytes seguintes e exige que ambos sejam zero.
                if (valueType == DataParser.DataType.STRING) {
                    candidateAddresses = candidateAddresses.filter { addr ->
                        initialPatterns.any { patternBytes ->
                            val readSize = patternBytes.size + 2
                            val data = Memory.read(processHandle, addr, readSize)
                            if (data != null && data.size >= readSize) {
                                val prefixMatches = data.copyOfRange(0, patternBytes.size).contentEquals(patternBytes)
                                val terminator = data.copyOfRange(patternBytes.size, patternBytes.size + 2)
                                val hasNullTerminator = terminator.all { b -> b.toInt() == 0 }
                                prefixMatches && hasNullTerminator
                            } else {
                                false
                            }
                        }
                    }
                }

                if (candidateAddresses.isEmpty()) {
                    println("Nenhum endereço encontrado para o valor informado.")
                } else {
                    println("Encontrados ${candidateAddresses.size} endereços.")
                }

                // Exibe os primeiros endereços ao usuário
                val initialReadSize = initialPatterns.maxOf { it.size }
                // Mostra o valor para cada endereço, usando o tamanho do maior padrão como bytes a ler
                printResults(candidateAddresses, processHandle, initialReadSize, valueType, maxDisplayCount)

                // Loop de refinamento: enquanto o usuário fornecer novos valores, filtra a lista
                while (candidateAddresses.isNotEmpty()) {
                    print("Novo valor para refinar (ENTER para encerrar): ")
                    val newValue = readlnOrNull()?.trim() ?: ""
                    if (newValue.isEmpty()) {
                        // Encerra se o usuário não quiser refinar mais
                        break
                    }

                    // Converte o novo valor para padrões de bytes (UTF-8 e UTF-16LE para strings)
                    val refinePatterns: List<ByteArray> = if (valueType == DataParser.DataType.STRING) {
                        listOf(
                            DataParser.toBytes(valueType, newValue),
                            DataParser.toBytesUtf16LE(newValue)
                        )
                    } else {
                        listOf(DataParser.toBytes(valueType, newValue))
                    }

                    candidateAddresses = if (valueType == DataParser.DataType.STRING) {
                        candidateAddresses.filter { addr ->
                            refinePatterns.any { patternBytes ->
                                val readSize = patternBytes.size + 2
                                val data = Memory.read(processHandle, addr, readSize)
                                if (data != null && data.size >= readSize) {
                                    val prefixMatches = data.copyOfRange(0, patternBytes.size).contentEquals(patternBytes)
                                    val terminator = data.copyOfRange(patternBytes.size, patternBytes.size + 2)
                                    val hasNullTerminator = terminator.all { b -> b.toInt() == 0 }
                                    prefixMatches && hasNullTerminator
                                } else {
                                    false
                                }
                            }
                        }
                    } else {
                        // Para tipos numéricos basta comparar o conteúdo exato do padrão
                        Memory.filterAddresses(processHandle, candidateAddresses, refinePatterns[0])
                    }

                    println("Restam ${candidateAddresses.size} endereços.")
                    if (candidateAddresses.isEmpty()) {
                        break
                    }
                    val refineReadSize = refinePatterns.maxOf { it.size }
                    // Mostra novamente os primeiros N endereços após o filtro
                    printResults(candidateAddresses, processHandle, refineReadSize, valueType, maxDisplayCount)
                }

            } finally {
                // Garante fechar o handle sempre
                Memory.close(processHandle)
            }
        }
    }
}


/**
 * Exibe uma lista de endereços de memória e seus respectivos valores ao usuário.
 * A listagem é limitada pelo parâmetro `maxShow` para evitar inundar a saída com
 * muitos resultados. Cada linha apresenta o valor lido interpretado de acordo
 * com o tipo de dado (`dataType`) seguido pelo endereço em hexadecimal.
 * Se houver mais resultados do que o limite, são mostrados apenas os primeiros
 * e uma reticência é impressa ao final.
 *
 * @param addresses Lista de endereços de memória encontrados.
 * @param handle Handle do processo usado para ler os valores.
 * @param bytesToRead Número de bytes a ler em cada endereço (tamanho do padrão original).
 * @param dataType Tipo dos dados, utilizado para formatar o valor para exibição.
 * @param maxShow Quantidade máxima de endereços a serem exibidos ao usuário.
 */
fun printResults(
    addresses: List<Long>,
    handle: WinNT.HANDLE,
    bytesToRead: Int,
    dataType: DataParser.DataType,
    maxShow: Int
) {
    val count = if (addresses.size > maxShow) maxShow else addresses.size
    for (i in 0 until count) {
        val addr = addresses[i]
        // Calcula a representação hexadecimal do endereço, sem prefixo
        val addrHex = addr.toString(16).uppercase().padStart(Native.POINTER_SIZE * 2, '0')
        // Lê os bytes da memória para exibir o valor em formato humano.  
        // Para strings, fazemos uma leitura mais longa (64 bytes) e tentamos decodificar
        // tanto em UTF‑8 quanto em UTF‑16LE, escolhendo a mais “imprimível”. Para
        // outros tipos, lemos exatamente o tamanho do padrão informado (size) e
        // decodificamos via DataParser.
        val valueStr = if (dataType == DataParser.DataType.STRING) {
            val peek = Memory.read(handle, addr, 64) ?: ByteArray(0)
            // tenta UTF-8 (corta no \0)
            val sUtf8 = runCatching {
                val raw = String(peek, Charsets.UTF_8)
                val cut = raw.indexOf('\u0000')
                if (cut >= 0) raw.take(cut) else raw
            }.getOrNull()
            // tenta UTF-16LE (corta no \0)
            val sUtf16 = runCatching {
                val raw = String(peek, Charsets.UTF_16LE)
                val cut = raw.indexOf('\u0000')
                if (cut >= 0) raw.take(cut) else raw
            }.getOrNull()
            listOfNotNull(sUtf16, sUtf8).maxByOrNull { s ->
                s.count { ch -> !ch.isISOControl() }
            } ?: ""
        } else {
            val bytes = Memory.read(handle, addr, bytesToRead)
            if (bytes != null) {
                runCatching { DataParser.fromBytes(dataType, bytes) }
                    .getOrElse { bytes.joinToString(" ") { b -> "%02X".format(b) } }
            } else {
                ""
            }
        }

        // Imprime linha formatada (UI.printLine adiciona prefixo '0x' ao endereço)
        println(UI.printLine(valueStr, addrHex))
    }
    if (addresses.size > maxShow) {
        println("...")
    }
}