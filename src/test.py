x = [{'month': 1, 'total': 600}, {'month': 1, 'total': 750}, {'month': 2, 'total': 800}, {'month': 3, 'total': 500},
     {'month': 2, 'total': 500}]

final = []
for y in x:
    if len(final) > 0:
        i = -1
        for z in range(len(final)):
            if y['month'] == final[z]['month']:
                i = z
            else:
                pass
        if i == -1:
            final.append(y)
        else:
            final[i]['total'] = final[i]['total'] + y['total']
    else:
        final.append(y)
print(final)

# print(a)

# print(y['month'])
# print(y['total'])
# if y['month'] not in [z['month'] for z in a]:
#     a.append({'month': y['month'], 'total': y['total']})
# else:
#     print('else----', y['total'])
#     for z in a:
#         z['total']+=y['total']
#         for b in a:
#
#             print(a['month'])
#             print(a['total'])
# print(a)
# print([z['month'] for z in a])
# print(['month' in x.values()])
# for key,value in y.items():
#     print(key,value)
# for y in x:
#     print(y.values())
