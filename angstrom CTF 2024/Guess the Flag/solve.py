import angr
import sys

base=0x400000
main=base+0x00000000000010e0
project = angr.Project('./guess_the_flag')
initial_state=project.factory.entry_state(addr=main)
simulation=project.factory.simgr(initial_state)

load_good_address=base+0x0000000000001159
simulation.explore(find=load_good_address)

if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('Could not find the solution')