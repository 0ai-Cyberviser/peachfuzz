import json
import random
import string

ATTACK_PAYLOADS = [
    {"endpoint": "../../etc/passwd"},
    {"endpoint": "//evil.example"},
    {"endpoint": "http://127.0.0.1"},
    {"endpoint": "javascript:alert(1)"},
    {"endpoint": ""},
    {"endpoint": None},
    {"endpoint": 123},
    {"endpoint": True},
    {"endpoint": ["nested", "list"]},
    {"endpoint": {"deep": "object"}},
]

def rand_str(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits + "/._-", k=length))


def deep_nest(depth=10):
    root = {"endpoint": "/v1/workflows"}
    cur = root
    for i in range(depth):
        cur["body"] = {"level": i}
        cur = cur["body"]
    return root


def mutate_json(payload: str) -> str:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"endpoint": payload[:32] or "/v1/workflows"}

    roll = random.random()

    # 🔥 inject attack payloads
    if roll < 0.25:
        return json.dumps(random.choice(ATTACK_PAYLOADS))

    # 🔥 deep nesting (parser stress)
    if roll < 0.45:
        return json.dumps(deep_nest(random.randint(5, 20)))

    # 🔥 structured mutation
    if isinstance(data, dict):
        data[rand_str()] = rand_str()

        if "endpoint" in data:
            data["endpoint"] = random.choice([
                rand_str(),
                "",
                None,
                123,
                True,
                ["bad"],
                {"bad": "shape"}
            ])

        for k in list(data.keys()):
            if random.random() < 0.2:
                data[k] = random.choice([rand_str(), None, 0, [], {}, True])

    elif isinstance(data, list):
        data.append(random.choice([rand_str(), None, 0, {}, []]))

    else:
        data = {"endpoint": data}

    return json.dumps(data)
