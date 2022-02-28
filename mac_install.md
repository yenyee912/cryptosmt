1. follow the instruction in the original cryptosmt repo, that one from ktse
2. install stp by follow the instruction
3. minisat is also instructed by stp repo
4. crptominisat DONT use the main branch
5. the branch I use in 29 jan 2022 is the crptominisat4
6. rename the /cryptominisat into /cryptominisat4 (at the root of repo)
7. configure the config.py in cryptosmt-boomerang/ ori repo --> this is to specify executable path
8. ** the example warp yaml is being located under /examples/warp/..yaml

9. USE THIS COMMAND TO RUN 
python3 cryptosmt-boomerang.py --input ./examples/warp/warp10-9-boomerang.yaml
IN CRYPTOSMT-BOOMERANG
