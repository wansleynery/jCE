import com.sun.jna.platform.win32.WinNT

/**
 * Classe principal da aplicação. Responsável por interagir com o usuário via CLI,
 * permitindo a seleção de um processo, a definição do tipo de dado e do valor a
 * pesquisar na memória desse processo e o refinamento sucessivo com novos valores.
 */
class Main {
    companion object {

        // Idioma das mensagens padrão (pode ser estendido no futuro)
        private const val DEFAULT_LANGUAGE = "ptBR"

        // Número máximo de endereços a serem mostrados ao usuário em cada etapa
        private const val DEFAULT_MAX_DISPLAY = 50

        @JvmStatic
        fun main (args: Array <String>) {

            App.setDefaultVariables (DEFAULT_LANGUAGE, DEFAULT_MAX_DISPLAY)

            App.allowProcessDebug ()

            var processHandle: WinNT.HANDLE? = null
            while (processHandle == null) {
                processHandle = App.selectProcess ()
            }

            try {
                while (true) App.expectCommand (processHandle)
            } finally {
                // Garante fechar o handle sempre
                Memory.close (processHandle)
            }
        }
    }
}
