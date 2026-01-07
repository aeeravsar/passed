# passed - Super Simple Stateless Password Manager
passed is a super simple stateless password manager

	$ passed
	usage: passed generate
           passed <domain> [counter]

	environment: PASSED_MNEMONIC

Let's generate our master key:

	$ passed generate
	thereupon admin sank properties sixty mariners outright depressive chap maneuver matched calculus letting consequent soloists hire

These 16 words are derived from a 16,384 words wordlist, meaning it's 2^224 possible combinations (16 × log₂(16384) = 16 × 14 = 224 bits of entropy). That's enough even for post-Grover's (224 ÷ 2 = 112), where our derived password has ~95 bits of entropy (16 characters, alphanumeric, capitals included, so 16 × log₂(62) ≈ 16 × 5.95 ≈ 95 bits of entropy). It is also ASIC/GPU resistant because of being 256MB memory hard Argon2id.

Now let's generate passwords, we will use the PASSED_MNEMONIC environment variable to provide our master key:

	$ export PASSED_MNEMONIC="thereupon admin sank properties sixty mariners outright depressive chap maneuver matched calculus letting consequent soloists hire"
	$ passed github.com
	c78YGaEHNC5OcD6F

That's it, you don't need to sync your passwords as long as you keep your master key safe.

And if you ever have to change your password on a site, just increase the counter by 1, where default is 0:

	$ passed github.com 1
	SqFBXoipTdJvFFEK

That's it.
