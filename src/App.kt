import UI.printResults
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinNT
import main.Properties

object App {

    private var defaultLanguage = "enUS"
    private var defaultMaxPointersShowed = 0
    private var addressList = mutableListOf <Long> ()
    private var lastTypeSearched: DataParser.DataType? = null
    // no topo do Aux
    var selectedPid: Int? = null
        private set

    fun setDefaultVariables (
        language: String,
        maxPointersShowed: Int
    ) {
        defaultLanguage = if (language !in arrayOf ("enUS", "ptBR")) "enUS" else language
        defaultMaxPointersShowed = if (maxPointersShowed > 100) 100 else maxPointersShowed
    }

    fun allowProcessDebug (): Boolean {

        val hProcess = Kernel32.INSTANCE.GetCurrentProcess ()
        val hToken   = WinNT.HANDLEByReference ()

        val okOpen = Advapi32.INSTANCE.OpenProcessToken (
            hProcess,
            WinNT.TOKEN_ADJUST_PRIVILEGES or WinNT.TOKEN_QUERY,
            hToken
        )
        if (!okOpen) return false

        val luid = WinNT.LUID ()
        val okLuid = Advapi32.INSTANCE.LookupPrivilegeValue (null, WinNT.SE_DEBUG_NAME, luid)
        if (!okLuid) {
            Kernel32.INSTANCE.CloseHandle (hToken.value)
            return false
        }

        val tp = WinNT.TOKEN_PRIVILEGES (1)
        tp.PrivilegeCount = WinDef.DWORD (1)
        tp.Privileges [0] = WinNT.LUID_AND_ATTRIBUTES ()              // <— instanciar o elemento!
        tp.Privileges [0].Luid = luid
        tp.Privileges [0].Attributes = WinDef.DWORD (WinNT.SE_PRIVILEGE_ENABLED.toLong ())

        val okAdj = Advapi32.INSTANCE.AdjustTokenPrivileges (
            hToken.value,
            false,
            tp,
            0,
            null,
            null
        )

        // Mesmo retornando true, pode não ter sido concedido: checar ERROR_NOT_ALL_ASSIGNED (1300)
        val last = Kernel32.INSTANCE.GetLastError ()
        Kernel32.INSTANCE.CloseHandle (hToken.value)

        return okAdj && last == 0

    }

    fun selectProcess (): WinNT.HANDLE? {

        print (Properties.get ("$defaultLanguage.prompt.enterProcess"))

        val input = readlnOrNull ()?.trim ().orEmpty ()
        if (input.isEmpty ()) {
            println (Properties.get ("$defaultLanguage.info.emptyInput"))
            return null
        }

        when (val r = Process.resolve (input)) {

            is Process.ResolveResult.NotFound -> {
                println (
                    Properties.get (
                        "$defaultLanguage.error.processNotFound",
                        mapOf ("processName" to input)
                    )
                )
                return null
            }

            is Process.ResolveResult.Single -> {
                val p = r.process
                selectedPid = p.processID
                println (
                    Properties.get (
                        "$defaultLanguage.info.selected",
                        mapOf (
                            "pid"  to p.processID.toString (),
                            "name" to (p.name ?: "")
                        )
                    )
                )
                return Process.open (p.processID)
            }

            is Process.ResolveResult.Multiple -> {
                val matches = r.matches

                println (
                    Properties.get (
                        "$defaultLanguage.info.foundN",
                        mapOf (
                            "count" to matches.size.toString (),
                            "query" to input
                        )
                    )
                )

                matches.forEachIndexed { idx, pair ->
                    val meta = pair.first.split (';') // "pid;exe;Pretty"
                    val pid  = meta.getOrNull (0) ?: "????"
                    val exe  = meta.getOrNull (1) ?: "unknown.exe"
                    val nice = meta.getOrNull (2) ?: exe
                    println ("  [$idx] PID $pid  -  $nice  ($exe)")
                }

                print (
                    Properties.get (
                        "$defaultLanguage.prompt.chooseIndex",
                        mapOf (
                            "min" to "0",
                            "max" to matches.lastIndex.toString ()
                        )
                    )
                )

                val pick = readlnOrNull ()?.trim ().orEmpty ()
                val i = pick.toIntOrNull ()
                if (i == null || i !in matches.indices) {
                    println (Properties.get ("$defaultLanguage.error.invalidIndex"))
                    return null
                }

                val chosen = matches [i].second
                selectedPid = chosen.processID
                println (
                    Properties.get (
                        "$defaultLanguage.info.selected",
                        mapOf (
                            "pid"  to chosen.processID.toString (),
                            "name" to (chosen.name ?: "")
                        )
                    )
                )
                return Process.open (chosen.processID)
            }
        }
    }

    // Solicita ao usuário o comando a ser feito
    // "search int 123" - cria nova pesquisa
    // "filter 124"     - refina a pesquisa
    // "set 123"        - altera para novo valor
    fun expectCommand (
        processHandle: WinNT.HANDLE
    ) {

        if (Command.handle == null) {
            Command.bind (processHandle)
        }

        print ("Informe o comando a ser executado (search <int-float-double-string> <valor> | filter <valor> | set <valor>): ")

        val inputCommand = readlnOrNull ()?.trim () ?: ""
        val commandList  = inputCommand.split (" ")

        if (commandList [0] == "search") {

            if (commandList.size < 3 || !arrayOf ("int", "float", "double", "string").contains (commandList [1])) {
                println ("O commando de search precisa ser no padrão \"search int 2\" ou \"search string blablabla\".")
                return
            }

            val type = when (commandList [1]) {
                "int"    -> DataParser.DataType.INT
                "float"  -> DataParser.DataType.FLOAT
                "double" -> DataParser.DataType.DOUBLE
                else     -> DataParser.DataType.STRING
            }
            lastTypeSearched = type

            val value = commandList.subList (2, commandList.size).joinToString (" ")

            val addressFound = Command.search (type, value)
            if (addressFound.isEmpty ()) {
                println ("Nenhum endereço encontrado. Inicie uma nova pesquisa com \"search <int-float-double-string> <value>\".")
                return
            } else {
                println ("Encontrados ${addressFound.size} endereços.")

                addressList.addAll (addressFound)

                // calcula o tamanho correto de leitura baseado no valor pesquisado
                val patterns = if (type == DataParser.DataType.STRING) {
                    listOf (
                        DataParser.toBytes (type, value),
                        DataParser.toBytesUtf16LE (value)
                    )
                } else {
                    listOf (DataParser.toBytes (type, value))
                }
                val bytesToRead = patterns.maxOf { it.size }

                // Mostra o valor para cada endereço, usando o tamanho do maior padrão como bytes a ler
                printResults (
                    addresses   = addressFound,
                    handle      = processHandle,
                    bytesToRead = bytesToRead,
                    dataType    = type,
                    maxShow     = defaultMaxPointersShowed
                )
            }

        }
        else if (commandList [0] == "filter") {

            if (commandList.size < 2) {
                println ("O commando de filter precisa ser do mesmo tipo e no padrão \"filter 2\" ou \"filter blablabla\".")
                return
            }

            if (addressList.isEmpty ()) {
                println ("Não há endereços de ponteiros a serem filtrados. Inicie uma nova pesquisa com \"search <int-float-double-string> <value>\".")
                return
            }

            val type = lastTypeSearched
            if (type == null) {
                println ("Tipo da última pesquisa não encontrado. Inicie uma nova pesquisa com \"search <int-float-double-string> <value>\".")
                return
            }

            val value = commandList.subList (1, commandList.size).joinToString (" ")

            val filteredAddresses = Command.filter (addressList, type, value)

            println ("Restam ${filteredAddresses.size} endereços.")
            if (filteredAddresses.isEmpty ()) {
                addressList.clear ()
                return
            }

            // calcula o tamanho correto de leitura baseado no valor filtrado
            val patterns = if (type == DataParser.DataType.STRING) {
                listOf (
                    DataParser.toBytes (type, value),
                    DataParser.toBytesUtf16LE (value)
                )
            } else {
                listOf (DataParser.toBytes (type, value))
            }
            val bytesToRead = patterns.maxOf { it.size }

            // Mostra "valor ... 0xENDERECO"
            printResults (
                addresses   = filteredAddresses,
                handle      = processHandle,
                bytesToRead = bytesToRead,
                dataType    = type,
                maxShow     = defaultMaxPointersShowed
            )

            // mantém o estado para próximos filtros/sets
            addressList.clear ()
            addressList.addAll (filteredAddresses)

        }
        else if (commandList [0] == "set") {

            if (commandList.size < 2) {
                println ("O commando de set precisa ser do mesmo tipo e no padrão \"set 2\" ou \"set blablabla\".")
                return
            }

            if (addressList.isEmpty ()) {
                println ("Não há endereços para alterar. Inicie uma pesquisa com \"search <int-float-double-string> <valor>\".")
                return
            }

            val type = lastTypeSearched
            if (type == null) {
                println ("Tipo da última pesquisa não encontrado. Inicie uma nova pesquisa com \"search <int-float-double-string> <valor>\".")
                return
            }

            val value = commandList.subList (1, commandList.size).joinToString (" ")

            val report = Command.set (addressList, type, value)

            val okCount   = report.updated.size
            val failCount = report.failed.size

            println ("Atualizados: $okCount | Falhas: $failCount")

            if (failCount > 0) {
                // Mostra só o primeiro erro de forma resumida
                val f = report.failed.first ()
                val addrHex = f.address.toString (16).uppercase ()
                println ("Falha exemplo: 0x$addrHex -> (${f.code}) ${f.message}")
            }

            if (okCount == 0) {
                return
            }

            // Atualiza a lista corrente para encadeamentos (filter/set subsequentes)
            addressList.clear ()
            addressList.addAll (report.updated)

            // Tamanho de leitura para exibir na listagem
            val bytesToRead: Int =
                if (type == DataParser.DataType.STRING) {
                    64  // printResults já tenta UTF-8 e UTF-16LE para mostrar texto
                } else {
                    DataParser.toBytes (type, value).size
                }

            // Mostra "valor ... 0xENDERECO" com o valor ATUAL (pós-set)
            printResults (
                addresses   = addressList,
                handle      = processHandle,
                bytesToRead = bytesToRead,
                dataType    = type,
                maxShow     = defaultMaxPointersShowed
            )

        }
        else if (commandList [0] == "pointer" || commandList [0] == "paddr") {

            if (commandList.size < 2) {
                println ("O commando pointer precisa receber um endereço: \"pointer 0x7FF...\" ou \"pointer 123456\".")
                return
            }

            val raw = commandList[1].trim()
            val target: Long = try {
                if (raw.startsWith ("0x", true)) {
                    raw.substring (2).toLong (16)
                } else {
                    raw.toLong ()
                }
            } catch (_: Exception) {
                println ("Endereço inválido: $raw")
                return
            }

            val pointers = Command.pointerScan (target, defaultMaxPointersShowed * 10)
            if (pointers.isEmpty ()) {
                println ("Nenhum ponteiro referenciando 0x${target.toString (16).uppercase ()} foi encontrado.")
                return
            }

            println ("Foram encontrados ${pointers.size} ponteiros para 0x${target.toString (16).uppercase ()}.")

            // mostra cada ponteiro no formato "target ..... 0xADDR"
            val displayCount = if (pointers.size > defaultMaxPointersShowed) defaultMaxPointersShowed else pointers.size
            for (i in 0 until displayCount) {
                val addr = pointers [i]
                val addrHex = addr.toString (16).uppercase ()
                println (UI.printLine (target.toString (), addrHex))
            }
            if (pointers.size > defaultMaxPointersShowed) println ("...")

            // substitui a lista corrente para poder aplicar filter/set a partir daqui
            addressList.clear ()
            addressList.addAll (pointers)
            lastTypeSearched = DataParser.DataType.INT // ponteiros são endereços inteiros para fins de set/filter

            return

        }
        else if (commandList [0] == "ptrs" || commandList [0] == "pointermany") {

            if (addressList.isEmpty ()) {
                println ("Não há endereços atuais. Faça uma busca (search) antes de rodar ptrs.")
                return
            }

            println ("Procurando referências para ${addressList.size} endereços (isso pode levar alguns segundos)...")

            val map = Command.pointerScanMany (addressList, defaultMaxPointersShowed * 5)

            var total = 0
            for ((t, list) in map) {
                if (list.isNotEmpty()) total += list.size
            }

            if (total == 0) {
                println ("Nenhum ponteiro encontrado apontando para os endereços atuais.")
                return
            }

            println ("Encontrados $total ponteiros no total.")

            var shown = 0
            for ((t, list) in map) {
                if (list.isEmpty()) continue
                val tHex = "0x${t.toString(16).uppercase()}"
                for (addr in list) {
                    if (shown >= defaultMaxPointersShowed) break
                    val addrHex = addr.toString(16).uppercase()
                    println (UI.printLine (t.toString (), addrHex))
                    shown++
                }
                if (shown >= defaultMaxPointersShowed) break
            }

            // atualiza addressList para trabalhar em cima dos ponteiros encontrados
            val allPtrs = map.values.flatten ().distinct ()
            addressList.clear ()
            addressList.addAll (allPtrs)
            lastTypeSearched = DataParser.DataType.INT

            return
        }
        else if (commandList [0] == "pointerchain" || commandList [0] == "pchain") {

            if (addressList.isEmpty ()) {
                println ("Não há endereços atuais para iniciar pointerchain. Faça uma busca (search) antes.")
                return
            }

            val depth = commandList.getOrNull(1)?.toIntOrNull() ?: 3
            println ("Executando pointer chain scan (depth=$depth)...")

            val chains = Command.pointerChainScan (addressList, maxDepth = depth, perLayerLimit = defaultMaxPointersShowed * 3)
            if (chains.isEmpty ()) {
                println ("Nenhuma cadeia encontrada.")
                return
            }

            println ("Foram geradas ${chains.size} cadeias (mostrando as $defaultMaxPointersShowed mais curtas).")

            // ordena por comprimento e mostra
            val sorted = chains.sortedBy { it.size }.take (defaultMaxPointersShowed)
            for (chain in sorted) {
                // format: 0xROOT -> 0x... -> 0xTARGET
                val line = chain.joinToString (" -> ") { "0x${it.toString(16).uppercase()}" }
                println (line)
            }

            return

        }
        else {
            println ("Comando inválido.")
        }

    }

}