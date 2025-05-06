package server;

import java.util.HashSet;

public class NonceTracker {

    // Set to store used nonces
    private final HashSet<String> seenNonces = new HashSet<>();

    // Check if a nonce has already been used
    public synchronized boolean isNonceUsed(String nonce) {
        return seenNonces.contains(nonce);
    }

    // Add a new nonce to the tracker
    public synchronized void addNonce(String nonce) {
        seenNonces.add(nonce);
    }

    public synchronized void clear() {
        seenNonces.clear();
    }
}
