#if canImport(SwiftUI)
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject var viewModel: AppViewModel
    @State private var isImportingRules = false

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("VPN Status")) {
                    HStack {
                        Text("Status")
                        Spacer()
                        Text(viewModel.vpnStatusTitle)
                            .foregroundColor(statusColor)
                    }
                }

                Section(
                    header: Text("Relay"),
                    footer: Text("The token is stored only in the shared Keychain and is cleared from this field after saving.")
                ) {
                    TextField("relay.example.com", text: $viewModel.relayHostname)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .keyboardType(.URL)
                    TextField("443", text: $viewModel.relayPort)
                        .keyboardType(.numberPad)
                    SecureField(
                        viewModel.hasSavedToken ? "Saved token (leave blank to keep)" : "64 hexadecimal characters",
                        text: $viewModel.tokenHex
                    )
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)

                    Button("Save and Install VPN") {
                        viewModel.saveAndInstall()
                    }
                    .disabled(!viewModel.canSaveAndInstall)
                }

                Section(
                    header: Text("DNS Upstreams"),
                    footer: Text("Enter IPv4 or IPv6 literals only. DIRECT and PROXY DNS actions never fall back to each other.")
                ) {
                    TextField("223.5.5.5", text: $viewModel.directDNSHost)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .keyboardType(.numbersAndPunctuation)
                    TextField("1.1.1.1", text: $viewModel.proxyDNSHost)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .keyboardType(.numbersAndPunctuation)
                }

                Section(header: Text("Rules"), footer: Text(viewModel.rulesStatus)) {
                    Button("Import JSON Rules") {
                        isImportingRules = true
                    }
                    .disabled(!viewModel.canImportRules)
                }

                Section(header: Text("Connection")) {
                    Button("Connect") {
                        viewModel.connect()
                    }
                    .disabled(!viewModel.canConnect)

                    Button("Disconnect", role: .destructive) {
                        viewModel.disconnect()
                    }
                    .disabled(!viewModel.canDisconnect)
                }

                if viewModel.isBusy {
                    Section {
                        HStack {
                            ProgressView()
                            Text("Working…")
                        }
                    }
                }

                if let errorMessage = viewModel.errorMessage {
                    Section(header: Text("Error")) {
                        Text(errorMessage)
                            .foregroundColor(.red)
                        Button("Dismiss") {
                            viewModel.clearError()
                        }
                    }
                }
            }
            .navigationTitle("iPad Proxy")
        }
        .navigationViewStyle(.stack)
        .fileImporter(
            isPresented: $isImportingRules,
            allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else {
                    viewModel.reportRuleSelectionFailure()
                    return
                }
                viewModel.importRules(from: url)
            case .failure:
                viewModel.reportRuleSelectionFailure()
            }
        }
        .onAppear { viewModel.load() }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                viewModel.refreshVPNProfile()
            case .background:
                viewModel.clearSensitiveInput()
            case .inactive:
                break
            @unknown default:
                viewModel.clearSensitiveInput()
            }
        }
    }

    private var statusColor: Color {
        switch viewModel.vpnStatus {
        case .connected:
            return .green
        case .connecting, .reasserting, .disconnecting:
            return .orange
        case .invalid, .disconnected:
            return .secondary
        }
    }
}
#endif
