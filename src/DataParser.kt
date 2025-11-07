import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Utilitário para converter valores de entrada em arrays de bytes, levando em consideração
 * diferentes tipos básicos (inteiro, float, double e string) e a ordem de bytes little-endian.
 *
 * Este objeto também oferece suporte para interpretar um array de bytes de volta em uma
 * representação de string do valor, útil para exibir resultados ao usuário.
 */
object DataParser {

    /**
     * Enumeração simples representando os tipos de dados suportados. Os nomes são
     * autodescritivos e serão usados ao converter valores para/desde arrays de bytes.
     */
    enum class DataType {
        INT,
        FLOAT,
        DOUBLE,
        STRING
    }

    /**
     * Analisa uma string informada pelo usuário e retorna o tipo de dado correspondente.
     * Os usuários podem fornecer abreviações como "i" para inteiro, "f" para float,
     * "d" para double ou "s" para string, bem como os nomes completos.
     *
     * @param input String informada pelo usuário.
     * @return DataType correspondente.
     * @throws IllegalArgumentException se a entrada não corresponder a nenhum tipo conhecido.
     */
    fun parseType(input: String): DataType {
        val normalized = input.trim().lowercase()
        return when (normalized) {
            "i", "int", "integer" -> DataType.INT
            "f", "float" -> DataType.FLOAT
            "d", "double" -> DataType.DOUBLE
            "s", "str", "string" -> DataType.STRING
            else -> throw IllegalArgumentException("Tipo de dado inválido: $input")
        }
    }

    /**
     * Converte um valor em string para um array de bytes no formato little-endian,
     * de acordo com o tipo de dado informado. Para strings, é utilizada a codificação UTF-8.
     *
     * @param type Tipo de dado a ser convertido.
     * @param value Valor textual informado pelo usuário.
     * @return Array de bytes representando o valor.
     */
    fun toBytes(type: DataType, value: String): ByteArray {
        return when (type) {
            DataType.INT -> {
                val v = value.toInt()
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
            }
            DataType.FLOAT -> {
                val v = value.toFloat()
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(v).array()
            }
            DataType.DOUBLE -> {
                val v = value.toDouble()
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(v).array()
            }
            DataType.STRING -> {
                value.toByteArray(Charsets.UTF_8)
            }
        }
    }

    /**
     * Converte um array de bytes de volta para uma representação de string do valor
     * de acordo com o tipo de dado. Para strings, utiliza a codificação UTF-8.
     *
     * @param type Tipo do valor armazenado no array de bytes.
     * @param bytes Array de bytes lido da memória do processo.
     * @return Representação textual do valor.
     */
    fun fromBytes(type: DataType, bytes: ByteArray): String {
        return when (type) {
            DataType.INT -> ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).int.toString()
            DataType.FLOAT -> ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).float.toString()
            DataType.DOUBLE -> ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).double.toString()
            DataType.STRING -> String(bytes, Charsets.UTF_8)
        }
    }


    fun toBytesUtf16LE(value: String): ByteArray =
        value.toByteArray(Charsets.UTF_16LE)

    fun fromBytesUtf16LE(bytes: ByteArray): String =
        String(bytes, Charsets.UTF_16LE)
}