# e

Remote shell between your macs. One file, no setup.

## home mac (leave running)

```bash
git clone https://github.com/000boil/e
cd e
python3 main.py
```

Copy the **code** it prints.

## other mac / school

```bash
git clone https://github.com/000boil/e
cd e
python3 main.py YOUR_CODE
```

That's it. Keep the home window open.

Same wifi fallback (if tunnel fails):

```bash
python3 main.py CODE --ip HOME_IP --key KEY_FROM_HOME_SCREEN
```

Needs python 3 + ssh (both on mac already).
