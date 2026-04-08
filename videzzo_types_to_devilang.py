import os
import argparse
import importlib
from videzzo_types_lib import Model, FIELD_RANDOM, FIELD_POINTER, FIELD_FLAG, FIELD_CONSTANT

def __gen_code(models, dirpath):
    os.system(f'rm -rf {dirpath}')
    os.makedirs(dirpath, exist_ok=True)
    for model_name, model in models.items():
        print('Handling {} ...'.format(model_name))
        if model.get_head() is None:
            continue
        with open(os.path.join(dirpath, model_name.split('_')[0] + '.devilang'), 'a') as f:
            f.write(model.get_data_model_devilang())
    print(f"Saved to {dirpath}")

def gen_types(output_dir):
    module = importlib.import_module('videzzo_types_gen_vmm')
    models = {}
    for k, v in module.__dict__.items():
        if isinstance(v, Model):
            models[k] = v
    __gen_code(models, output_dir)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate devilang model files from videzzo types')
    parser.add_argument('-o', '--output', default='models', help='Output directory for generated model files')
    args = parser.parse_args()
    gen_types(args.output)
