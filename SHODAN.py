
import os
import sys
import argparse
from collections import Counter
from shodan import Shodan, APIError 

PER_PAGE = 100  # Shodan devuelve hasta 100 resultados por página

def parse_args():
    p = argparse.ArgumentParser(description="Buscar en Shodan (Guatemala) y generar resumen.")
    p.add_argument('--filter', '-f', default='country:"GT"',
                   help='Filtro de búsqueda Shodan (ej: city:"Jalapa" country:"GT"). Se prohibe org:.')
    p.add_argument('--api-key', '-k', default=None, help='Shodan API key (opcional).')
    p.add_argument('--max-results', '-m', type=int, default=None,
                   help='Máximo de resultados a recuperar (para pruebas). Por defecto, recupera todos.')
    # Datos del alumno (requeridos según tu consigna)
    p.add_argument('--carnet', required=True, help='Número de carnet del alumno')
    p.add_argument('--name', required=True, help='Nombre completo del alumno')
    p.add_argument('--course', required=True, help='Curso')
    p.add_argument('--section', required=True, help='Sección')
    return p.parse_args()

def validate_filter(q):
    if 'org:' in q.lower():
        raise ValueError('El uso de filtros por organización (org:) está prohibido.')

def human_print_match(m):
    # Impresión legible de cada match
    ip = m.get('ip_str', 'N/A')
    port = m.get('port', 'N/A')
    ts = m.get('timestamp', '')
    hostnames = m.get('hostnames', [])
    product = m.get('product') or m.get('title') or ''
    data_snippet = m.get('data', '')[:300].replace('\n', '\\n') 
    print(f"---")
    print(f"IP: {ip}\tPuerto: {port}\tTimestamp: {ts}")
    if hostnames:
        print(f"Hostnames: {', '.join(hostnames)}")
    if product:
        print(f"Product: {product}")
    print(f"Banner (recortada): {data_snippet}")
    # Opcional: mostrar otros campos útiles si existen
    if 'org' in m:
        print(f"Org: {m.get('org')}")
    if 'asn' in m:
        print(f"ASN: {m.get('asn')}")
    if 'location' in m:
        loc = m['location']
        city = loc.get('city') or ''
        country = loc.get('country_name') or ''
        print(f"Location: {city} - {country}")
    print()

def main():
    args = parse_args()

    # Validar filtro
    try:
        validate_filter(args.filter)
    except ValueError as e:
        print(f"Filtro inválido: {e}", file=sys.stderr)
        sys.exit(1)

    api_key = args.api_key or os.getenv('SHODAN_API_KEY')
    if not api_key:
        print("Error: no se encontró la API key de Shodan. Usa --api-key o exporta SHODAN_API_KEY.", file=sys.stderr)
        sys.exit(1)

    api = Shodan(api_key)

    query = args.filter
    max_results = args.max_results

    print(f"Búsqueda Shodan con filtro: {query}")
    if max_results:
        print(f"Límite de resultados solicitado: {max_results}")

    all_matches = []
    page = 1
    total_estimated = None
    try:
        # Primera llamada para obtener total
        res = api.search(query, page=page)
        total_estimated = res.get('total', 0)
        print(f"Resultados totales (estimado por Shodan): {total_estimated}")
        matches = res.get('matches', [])
        all_matches.extend(matches)

        # Si hay más páginas y no sobrepasamos max_results, iterar
        # Shodan usa page número comenzando en 1
        while True:
            # Chequear si debemos parar por max_results
            if max_results and len(all_matches) >= max_results:
                all_matches = all_matches[:max_results]
                break

            # Calcular si necesitamos siguiente página
            # Si la cantidad obtenida hasta ahora >= total_estimated -> terminar
            if len(all_matches) >= total_estimated:
                break

            page += 1
            try:
                res = api.search(query, page=page)
            except APIError as e:
                # Cuando no hay más páginas, Shodan puede lanzar un error; rompemos
                print(f"Fin de páginas o error al pedir página {page}: {e}", file=sys.stderr)
                break
            matches = res.get('matches', [])
            if not matches:
                break
            all_matches.extend(matches)

    except APIError as e:
        print(f"Error en la búsqueda de Shodan: {e}", file=sys.stderr)
        sys.exit(1)

    # Mostrar todos los resultados en consola
    print("\n\n*** RESULTADOS OBTENIDOS ***\n")
    for m in all_matches:
        human_print_match(m)

    # Generar resumen
    ips = set()
    port_counter = Counter()
    for m in all_matches:
        ip = m.get('ip_str')
        if ip:
            ips.add(ip)
        # Cada match tiene un puerto 'port' (servicio encontrado). Contamos por puerto.
        p = m.get('port')
        if p:
            port_counter[p] += 1
        # Ocasionalmente un campo 'ports' (lista) puede aparecer en agregados - intentar contarlas también
        if 'ports' in m and isinstance(m['ports'], (list, tuple)):
            for p2 in m['ports']:
                port_counter[p2] += 1

    # Imprimir resumen
    print("\n\n*** RESUMEN ***")
    print(f"Alumno: {args.name}")
    print(f"Carnet: {args.carnet}")
    print(f"Curso: {args.course}")
    print(f"Sección: {args.section}")
    print("----")
    print(f"Total direcciones IP identificadas (únicas): {len(ips)}")
    print("Total de apariciones por puerto (ordenado):")
    if port_counter:
        for port, count in port_counter.most_common():
            print(f"  Puerto {port}: {count} apariciones")
    else:
        print("  Ningún puerto contado.")

    print("\nHecho.")

if __name__ == '__main__':
    main()
