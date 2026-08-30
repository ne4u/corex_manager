import { useCallback, useEffect, useState } from 'react'

export default function useApiList<T = any>(fetcher: () => Promise<{ data: T[] }>) {
  const [items, setItems] = useState<T[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetcher()
      setItems(res.data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [fetcher])

  useEffect(() => {
    load()
  }, [load])

  return { items, setItems, loading, reload: load }
}
