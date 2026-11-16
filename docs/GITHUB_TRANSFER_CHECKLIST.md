# GitHub setup and transfer to the supervisor (urgent: the professor asked for it by Oct 31)

1. Owner creates the repo (e.g. `group7a-ransomware-early-warning-agent`) and pushes this folder:
   ```bash
   git init && git add . && git commit -m "Group 7A MVP: ransomware early-warning agent"
   git branch -M main
   git remote add origin https://github.com/<owner>/group7a-ransomware-early-warning-agent.git
   git push -u origin main
   ```
2. Settings → Collaborators → invite the 4 teammates.
3. Settings → General → Danger Zone → **Transfer** → *Specify an organization or username* → `farhadabbasiamiri` (exact, personal account) → type the repo name → confirm.
4. Email the professor: original URL, repo name, "Group 7A", transfer initiated (he must accept within 24 h).
5. After acceptance, every member runs:
   ```bash
   git remote set-url origin https://github.com/farhadabbasiamiri/group7a-ransomware-early-warning-agent.git
   git fetch origin
   ```
6. Each member confirms they can pull, branch, push, and open a PR. Send the professor the new link.
