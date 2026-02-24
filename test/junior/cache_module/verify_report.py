import json

defects_path = 'c:/Users/10273/home/work/Z-Scope/test/junior/cache_module/defects.json'
report_path = 'c:/Users/10273/home/work/Z-Scope/test/junior/cache_module/zscope_batch_report.json'

with open(defects_path, 'r', encoding='utf-8') as f:
    defects = json.load(f)

with open(report_path, 'r', encoding='utf-8') as f:
    report = json.load(f)

expected_issues = defects['tiers'][0]['modules'][0]['defects']
found_issues = report['issues']

print('--- MAPPING ---')
matched_count = 0
for exp in expected_issues:
    func_name = exp['function'].replace('()', '')
    print(f"\nExpected [{exp['id']}]: {func_name}() - {exp['type']} ({exp['description']})")
    matches = [i for i in found_issues if i['function'] == func_name]
    
    # Simple manual matching string for easier reading
    if not matches:
        print('  -> [MISSED]')
    else:
        found_match = False
        for m in matches:
            sub = m.get('subcategory', '')
            cat = m.get('category', '')
            desc = m.get('description', '')
            val = m.get('validation_status', '')
            print(f"  -> FOUND in same function: {m['id']} | {cat}/{sub} | {m['location']} | Validation: {val}")
            print(f"     Description: {desc[:60]}...")
            
            # Very loose matching logic for proof of concept
            if m['validation_status'] == 'validated':
                found_match = True
        
        if found_match:
           matched_count += 1

print(f"\nTotal: Validated hits in {matched_count}/{len(expected_issues)} target functions.")
