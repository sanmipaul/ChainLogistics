# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - link "Skip to main content" [ref=e2] [cursor=pointer]:
    - /url: "#main-content"
  - generic [ref=e3]:
    - navigation "Main navigation" [ref=e4]:
      - generic [ref=e5]:
        - link "ChainLogistics" [ref=e6] [cursor=pointer]:
          - /url: /dashboard
        - generic [ref=e7]:
          - generic [ref=e8]:
            - link "Dashboard" [ref=e9] [cursor=pointer]:
              - /url: /dashboard
            - link "Register Product" [ref=e10] [cursor=pointer]:
              - /url: /register
            - link "Tracking" [ref=e11] [cursor=pointer]:
              - /url: /tracking
          - button "Connect Freighter wallet" [ref=e14]:
            - img
            - text: Connect Wallet
    - main [ref=e15]:
      - main [ref=e16]:
        - generic [ref=e17]:
          - heading "Product Registration" [level=1] [ref=e18]
          - paragraph [ref=e19]: Registers your product assets on the Stellar blockchain for verified tracking.
        - generic [ref=e20]:
          - img [ref=e22]
          - heading "Registration Successful!" [level=2] [ref=e25]
          - paragraph [ref=e26]: Your product has been registered on the Stellar blockchain.
          - paragraph [ref=e28]: "Transaction Hash: t_9h0reqniu6t"
          - button "View Dashboard" [ref=e29]
  - region "Notifications alt+T"
  - alert [ref=e30]
```