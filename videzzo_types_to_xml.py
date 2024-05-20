import importlib
from videzzo_types_lib import Model, FIELD_RANDOM, FIELD_POINTER, FIELD_FLAG, FIELD_CONSTANT

def __gen_code(models):
    filepath = 'videzzo_data_models.xml'
    with open(filepath, 'w') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<VirtLang>\n')
        for model_name, model in models.items():
            print('Handling {} ...'.format(model_name))
            if model.get_head() is None:
                continue
            f.write('    <!-- Data Models for {} -->\n'.format(model_name))
            f.write(model.get_xml())
        f.write('</VirtLang>')
        print('\tin {}'.format(filepath))

def gen_types():
    module = importlib.import_module('videzzo_types_gen_vmm')
    models = {}
    for k, v in module.__dict__.items():
        if isinstance(v, Model):
            models[k] = v
    __gen_code(models)

if __name__ == '__main__':
    gen_types()
