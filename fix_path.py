#!/usr/bin/python3

import os
import re

def get_all_automation_files(directory):
    automation_files = []
    
    for root, dirs, files in os.walk(directory):
        if root == '.': # skip the current directory because this contain base automation files and not helper files
            continue
        if re.match(r'^.*helper_[0-9a-f]{6}$', root):
            for file in files:
                automation_files.append(os.path.join(root, file))
    
    return automation_files

def fix_config_path(file):
    with open(file, 'r') as f:
        lines = f.readlines()
    
    config_line_index = 0
    for i in range(len(lines)):
        if 'config_file = ' in lines[i]:
            config_line_index = i
            break
    
    #Credits: ChatGPT for next three lines
    current_path = os.path.normpath(os.getcwd())
    current_path = current_path.replace("\\", "/")
    line = re.sub(r'(\.join\(r\")(.*?)(\", )', rf'\1{current_path}\3', lines[config_line_index])

    lines[config_line_index] = line

    with open(file, 'w') as f:
        f.writelines(lines)



files = get_all_automation_files('.')

for file in files:
    fix_config_path(file)