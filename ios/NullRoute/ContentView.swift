import SwiftUI

@main
struct NullRouteApp: App {
    @StateObject private var manager = BlockerManager()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(manager)
                .tint(Color("Route"))
        }
        .onChange(of: scenePhase) { phase in
            // Users enable blockers in Settings, then come back here.
            if phase == .active { Task { await manager.refreshState() } }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var manager: BlockerManager
    @State private var newSite = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(alignment: .firstTextBaseline) {
                        Text("\(manager.enabledCount)")
                            .font(.system(size: 52, weight: .bold, design: .rounded))
                            .monospacedDigit()
                        Text("of \(Blocker.allCases.count) blockers on in Safari")
                            .foregroundStyle(.secondary)
                    }
                    .listRowBackground(Color.clear)
                }

                Section {
                    ForEach(Blocker.allCases) { blocker in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(blocker.title)
                                Text(blocker.detail).font(.footnote).foregroundStyle(.secondary)
                            }
                            Spacer()
                            StatusPill(on: manager.enabled[blocker] ?? false)
                        }
                    }
                } header: {
                    Text("Safari blockers")
                } footer: {
                    if manager.enabledCount < Blocker.allCases.count {
                        Text("Turn them on in Settings › Apps › Safari › Extensions (on iOS 17 and earlier: Settings › Safari › Extensions). Come back here and the status updates.")
                    }
                }

                Section {
                    ForEach(manager.allowlist, id: \.self) { site in
                        Text(site).font(.body.monospaced())
                    }
                    .onDelete { indexes in
                        let sites = indexes.map { manager.allowlist[$0] }
                        Task { for s in sites { await manager.remove(s) } }
                    }
                    HStack {
                        TextField("example.com", text: $newSite)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                            .submitLabel(.done)
                            .onSubmit(addSite)
                        Button("Allow", action: addSite).disabled(newSite.isEmpty || manager.busy)
                    }
                } header: {
                    Text("Allowed sites")
                } footer: {
                    Text("Nothing is blocked or hidden on these sites or their subdomains.")
                }

                Section {
                    LabeledContent("Last updated") {
                        Text(manager.lastUpdated.map { $0.formatted(date: .abbreviated, time: .omitted) } ?? "Bundled with app")
                    }
                    Button {
                        Task { await manager.updateLists() }
                    } label: {
                        HStack {
                            Text(manager.busy ? "Working…" : "Check for updates")
                            if manager.busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(manager.busy)
                    if let message = manager.message {
                        Text(message).font(.footnote).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Filter lists")
                } footer: {
                    Text("EasyList, EasyPrivacy (GPLv3 / CC BY-SA 3.0) and StevenBlack hosts (MIT). Updates are verified with SHA-256 before they're installed. Safari applies the rules itself — NullRoute never sees the sites you visit.")
                }
            }
            .navigationTitle("NullRoute")
            .refreshable { await manager.refreshState() }
            .task { await manager.refreshState() }
        }
    }

    private func addSite() {
        let site = newSite
        newSite = ""
        Task { await manager.allow(site) }
    }
}

private struct StatusPill: View {
    let on: Bool
    var body: some View {
        Text(on ? "On" : "Off")
            .font(.footnote.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(on ? Color("Route").opacity(0.15) : Color.secondary.opacity(0.12), in: Capsule())
            .foregroundStyle(on ? Color("Route") : .secondary)
            .accessibilityLabel(on ? "Enabled" : "Disabled")
    }
}
